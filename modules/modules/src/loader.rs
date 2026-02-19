use std::ffi::{CStr, CString};
use std::path::Path;

use crate::base::{Module, ModuleContext, ModuleError, ModuleResult};
use crate::contract::ModuleCompatibilityPolicy;
use crate::json::{parse_json, JsonValue};
use crate::manifest::ModuleManifest;
use crate::metadata::ModuleMetadata;
use crate::options::{ModuleOption, ModuleOptionKind, ModuleOptionValue, ModuleOptions};

#[repr(C)]
pub struct ModuleResultV1 {
    pub success: u8,
    pub message: *const libc::c_char,
}

#[repr(C)]
pub struct ModuleApiV1 {
    pub api_version: u32,
    pub struct_size: u32,
    pub get_metadata_json: Option<extern "C" fn() -> *const libc::c_char>,
    pub get_options_json: Option<extern "C" fn() -> *const libc::c_char>,
    pub create: Option<extern "C" fn() -> *mut libc::c_void>,
    pub destroy: Option<extern "C" fn(*mut libc::c_void)>,
    pub set_option:
        Option<extern "C" fn(*mut libc::c_void, *const libc::c_char, *const libc::c_char) -> i32>,
    pub run: Option<extern "C" fn(*mut libc::c_void, *const libc::c_char) -> ModuleResultV1>,
    pub free_string: Option<extern "C" fn(*const libc::c_char)>,
}

type ModuleApiFn = extern "C" fn() -> *const ModuleApiV1;

pub fn load_dyn_module(path: &Path) -> Result<Box<dyn Module>, ModuleError> {
    let lib = LibraryHandle::open(path)?;
    let api_fn: ModuleApiFn = unsafe { lib.symbol("moonlight_module_v1")? };
    let api_ptr = api_fn();
    if api_ptr.is_null() {
        return Err(ModuleError::Execution(
            "module API pointer is null".to_string(),
        ));
    }
    let api = unsafe { &*api_ptr };
    let exported_api_version = validate_api(api)?;

    let metadata_json = read_api_string(api.get_metadata_json, api.free_string)?;
    let manifest = ModuleManifest::parse_str(&metadata_json)
        .map_err(|e| ModuleError::Execution(format!("metadata parse error: {e}")))?;
    let policy = ModuleCompatibilityPolicy::dynlib_loader_default();
    manifest
        .validate_dynlib_compatibility(&policy, exported_api_version)
        .map_err(|e| ModuleError::Execution(format!("metadata compatibility error: {e}")))?;
    let metadata = manifest.metadata;
    let options = if let Some(get_options) = api.get_options_json {
        let options_json = read_api_string(Some(get_options), api.free_string)?;
        parse_options_json(&options_json)?
    } else {
        ModuleOptions::new(Vec::new())
    };

    let create = api
        .create
        .ok_or_else(|| ModuleError::Execution("missing create()".to_string()))?;
    let handle = create();
    if handle.is_null() {
        return Err(ModuleError::Execution(
            "module create() returned null".to_string(),
        ));
    }

    Ok(Box::new(DynModule {
        _lib: lib,
        api_ptr,
        handle,
        metadata,
        options,
    }))
}

struct DynModule {
    _lib: LibraryHandle,
    api_ptr: *const ModuleApiV1,
    handle: *mut libc::c_void,
    metadata: ModuleMetadata,
    options: ModuleOptions,
}

impl DynModule {
    fn api(&self) -> &ModuleApiV1 {
        unsafe { &*self.api_ptr }
    }

    fn apply_options(&mut self) -> Result<(), ModuleError> {
        let api = self.api();
        let set_option = api
            .set_option
            .ok_or_else(|| ModuleError::Execution("missing set_option()".to_string()))?;
        for opt in self.options.iter() {
            let value = opt.value.as_ref().or(opt.default.as_ref());
            let Some(value) = value else {
                continue;
            };
            let key = CString::new(opt.name.as_str())
                .map_err(|_| ModuleError::Execution("option name contains null".to_string()))?;
            let val = CString::new(value.as_string())
                .map_err(|_| ModuleError::Execution("option value contains null".to_string()))?;
            let rc = set_option(self.handle, key.as_ptr(), val.as_ptr());
            if rc != 0 {
                return Err(ModuleError::Execution(format!(
                    "set_option failed for {}",
                    opt.name
                )));
            }
        }
        Ok(())
    }
}

impl Module for DynModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.metadata
    }

    fn options(&self) -> &ModuleOptions {
        &self.options
    }

    fn options_mut(&mut self) -> &mut ModuleOptions {
        &mut self.options
    }

    fn run(&mut self, ctx: &ModuleContext) -> Result<ModuleResult, ModuleError> {
        self.options.validate().map_err(ModuleError::Validation)?;
        self.apply_options()?;
        let api = self.api();
        let run = api
            .run
            .ok_or_else(|| ModuleError::Execution("missing run()".to_string()))?;
        let ctx_json = format!("{{\"session_id\":{}}}", ctx.session_id);
        let ctx_cstr = CString::new(ctx_json)
            .map_err(|_| ModuleError::Execution("context contains null".to_string()))?;
        let result = run(self.handle, ctx_cstr.as_ptr());
        let message = read_c_string(result.message, api.free_string)?;
        Ok(ModuleResult {
            success: result.success != 0,
            message,
            session: None,
        })
    }
}

impl Drop for DynModule {
    fn drop(&mut self) {
        let api = self.api();
        if let Some(destroy) = api.destroy {
            destroy(self.handle);
        }
    }
}

unsafe impl Send for DynModule {}

fn validate_api(api: &ModuleApiV1) -> Result<u32, ModuleError> {
    let policy = ModuleCompatibilityPolicy::dynlib_loader_default();
    if !policy.supports_module_api_version(api.api_version) {
        return Err(ModuleError::Execution(format!(
            "unsupported API version: {}",
            api.api_version
        )));
    }
    if (api.struct_size as usize) < std::mem::size_of::<ModuleApiV1>() {
        return Err(ModuleError::Execution(
            "API struct size too small".to_string(),
        ));
    }
    if api.get_metadata_json.is_none() {
        return Err(ModuleError::Execution(
            "missing get_metadata_json()".to_string(),
        ));
    }
    if api.free_string.is_none() {
        return Err(ModuleError::Execution("missing free_string()".to_string()));
    }
    Ok(api.api_version)
}

fn read_api_string(
    getter: Option<extern "C" fn() -> *const libc::c_char>,
    free: Option<extern "C" fn(*const libc::c_char)>,
) -> Result<String, ModuleError> {
    let getter = getter.ok_or_else(|| ModuleError::Execution("missing getter".to_string()))?;
    let ptr = getter();
    read_c_string(ptr, free)
}

fn read_c_string(
    ptr: *const libc::c_char,
    free: Option<extern "C" fn(*const libc::c_char)>,
) -> Result<String, ModuleError> {
    if ptr.is_null() {
        return Ok(String::new());
    }
    let text = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| ModuleError::Execution("invalid UTF-8 from module".to_string()))?
        .to_string();
    if let Some(free) = free {
        free(ptr);
    }
    Ok(text)
}

fn parse_options_json(input: &str) -> Result<ModuleOptions, ModuleError> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(ModuleOptions::new(Vec::new()));
    }
    let value = parse_json(trimmed).map_err(|e| ModuleError::Execution(e.to_string()))?;
    let JsonValue::Array(items) = value else {
        return Err(ModuleError::Execution(
            "options JSON must be an array".to_string(),
        ));
    };
    let mut options = Vec::with_capacity(items.len());
    for item in items {
        let JsonValue::Object(map) = item else {
            continue;
        };
        let name = get_str(&map, "name")?;
        let description = get_str(&map, "description").unwrap_or_else(|_| "".to_string());
        let kind = get_str(&map, "kind").unwrap_or_else(|_| "string".to_string());
        let required = get_bool(&map, "required").unwrap_or(false);
        let mut option = ModuleOption::new(&name, &description, parse_kind(&kind)?, required);
        if let Some(default) = map.get("default") {
            let val = parse_default(default, &option.kind)?;
            option = option.with_default(val);
        }
        options.push(option);
    }
    Ok(ModuleOptions::new(options))
}

fn get_str(
    map: &std::collections::BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<String, ModuleError> {
    match map.get(key) {
        Some(JsonValue::String(value)) => Ok(value.clone()),
        Some(_) => Err(ModuleError::Execution(format!(
            "option field '{key}' must be a string"
        ))),
        None => Err(ModuleError::Execution(format!(
            "option field '{key}' missing"
        ))),
    }
}

fn get_bool(
    map: &std::collections::BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<bool, ModuleError> {
    match map.get(key) {
        Some(JsonValue::Bool(value)) => Ok(*value),
        Some(_) => Err(ModuleError::Execution(format!(
            "option field '{key}' must be a bool"
        ))),
        None => Err(ModuleError::Execution(format!(
            "option field '{key}' missing"
        ))),
    }
}

fn parse_kind(input: &str) -> Result<ModuleOptionKind, ModuleError> {
    match input.to_ascii_lowercase().as_str() {
        "string" => Ok(ModuleOptionKind::String),
        "bool" | "boolean" => Ok(ModuleOptionKind::Bool),
        "int" | "integer" => Ok(ModuleOptionKind::Integer),
        "address" | "addr" => Ok(ModuleOptionKind::Address),
        "port" => Ok(ModuleOptionKind::Port),
        other => Err(ModuleError::Execution(format!(
            "unknown option kind: {other}"
        ))),
    }
}

fn parse_default(
    value: &JsonValue,
    kind: &ModuleOptionKind,
) -> Result<ModuleOptionValue, ModuleError> {
    match kind {
        ModuleOptionKind::String => match value {
            JsonValue::String(v) => Ok(ModuleOptionValue::String(v.clone())),
            _ => Err(ModuleError::Execution("default must be string".to_string())),
        },
        ModuleOptionKind::Bool => match value {
            JsonValue::Bool(v) => Ok(ModuleOptionValue::Bool(*v)),
            _ => Err(ModuleError::Execution("default must be bool".to_string())),
        },
        ModuleOptionKind::Integer => match value {
            JsonValue::Number(v) => Ok(ModuleOptionValue::Integer(*v as i64)),
            _ => Err(ModuleError::Execution("default must be number".to_string())),
        },
        ModuleOptionKind::Address => match value {
            JsonValue::String(v) => Ok(ModuleOptionValue::Address(v.clone())),
            _ => Err(ModuleError::Execution("default must be string".to_string())),
        },
        ModuleOptionKind::Port => match value {
            JsonValue::Number(v) => Ok(ModuleOptionValue::Port(*v as u16)),
            _ => Err(ModuleError::Execution("default must be number".to_string())),
        },
    }
}

struct LibraryHandle {
    handle: *mut libc::c_void,
}

impl LibraryHandle {
    fn open(path: &Path) -> Result<Self, ModuleError> {
        let handle = unsafe { platform_open(path)? };
        Ok(LibraryHandle { handle })
    }

    unsafe fn symbol<T>(&self, name: &str) -> Result<T, ModuleError>
    where
        T: Copy,
    {
        let symbol = platform_symbol(self.handle, name)?;
        Ok(std::mem::transmute_copy(&symbol))
    }
}

impl Drop for LibraryHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = platform_close(self.handle);
        }
    }
}

#[cfg(unix)]
unsafe fn platform_open(path: &Path) -> Result<*mut libc::c_void, ModuleError> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ModuleError::Execution("invalid library path".to_string()))?;
    let handle = libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW);
    if handle.is_null() {
        return Err(ModuleError::Execution(dl_error()));
    }
    Ok(handle)
}

#[cfg(unix)]
unsafe fn platform_symbol(
    handle: *mut libc::c_void,
    name: &str,
) -> Result<*mut libc::c_void, ModuleError> {
    let c_name = CString::new(name)
        .map_err(|_| ModuleError::Execution("invalid symbol name".to_string()))?;
    let symbol = libc::dlsym(handle, c_name.as_ptr());
    if symbol.is_null() {
        return Err(ModuleError::Execution(dl_error()));
    }
    Ok(symbol)
}

#[cfg(unix)]
unsafe fn platform_close(handle: *mut libc::c_void) -> Result<(), ModuleError> {
    if handle.is_null() {
        return Ok(());
    }
    if libc::dlclose(handle) != 0 {
        return Err(ModuleError::Execution(dl_error()));
    }
    Ok(())
}

#[cfg(unix)]
fn dl_error() -> String {
    unsafe {
        let err = libc::dlerror();
        if err.is_null() {
            return "unknown dlerror".to_string();
        }
        CStr::from_ptr(err).to_string_lossy().to_string()
    }
}

#[cfg(windows)]
unsafe fn platform_open(path: &Path) -> Result<*mut libc::c_void, ModuleError> {
    let path = path.to_string_lossy();
    let c_path = CString::new(path.as_bytes())
        .map_err(|_| ModuleError::Execution("invalid library path".to_string()))?;
    let handle = LoadLibraryA(c_path.as_ptr());
    if handle.is_null() {
        return Err(ModuleError::Execution("LoadLibrary failed".to_string()));
    }
    Ok(handle as *mut libc::c_void)
}

#[cfg(windows)]
unsafe fn platform_symbol(
    handle: *mut libc::c_void,
    name: &str,
) -> Result<*mut libc::c_void, ModuleError> {
    let c_name = CString::new(name)
        .map_err(|_| ModuleError::Execution("invalid symbol name".to_string()))?;
    let symbol = GetProcAddress(handle as *mut _, c_name.as_ptr());
    if symbol.is_null() {
        return Err(ModuleError::Execution("GetProcAddress failed".to_string()));
    }
    Ok(symbol as *mut libc::c_void)
}

#[cfg(windows)]
unsafe fn platform_close(handle: *mut libc::c_void) -> Result<(), ModuleError> {
    if handle.is_null() {
        return Ok(());
    }
    let ok = FreeLibrary(handle as *mut _);
    if ok == 0 {
        return Err(ModuleError::Execution("FreeLibrary failed".to_string()));
    }
    Ok(())
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lpLibFileName: *const libc::c_char) -> *mut libc::c_void;
    fn GetProcAddress(
        hModule: *mut libc::c_void,
        lpProcName: *const libc::c_char,
    ) -> *mut libc::c_void;
    fn FreeLibrary(hModule: *mut libc::c_void) -> i32;
}
