use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;

#[repr(C)]
pub struct ModuleResultV1 {
    pub success: u8,
    pub message: *const c_char,
}

#[repr(C)]
pub struct ModuleApiV1 {
    pub api_version: u32,
    pub struct_size: u32,
    pub get_metadata_json: Option<extern "C" fn() -> *const c_char>,
    pub get_options_json: Option<extern "C" fn() -> *const c_char>,
    pub create: Option<extern "C" fn() -> *mut c_void>,
    pub destroy: Option<extern "C" fn(*mut c_void)>,
    pub set_option: Option<extern "C" fn(*mut c_void, *const c_char, *const c_char) -> i32>,
    pub run: Option<extern "C" fn(*mut c_void, *const c_char) -> ModuleResultV1>,
    pub free_string: Option<extern "C" fn(*const c_char)>,
}

struct ModuleState {
    input: String,
}

static API: ModuleApiV1 = ModuleApiV1 {
    api_version: 1,
    struct_size: std::mem::size_of::<ModuleApiV1>() as u32,
    get_metadata_json: Some(get_metadata_json),
    get_options_json: Some(get_options_json),
    create: Some(create),
    destroy: Some(destroy),
    set_option: Some(set_option),
    run: Some(run),
    free_string: Some(free_string),
};

#[no_mangle]
pub extern "C" fn moonlight_module_v1() -> *const ModuleApiV1 {
    &API as *const ModuleApiV1
}

extern "C" fn get_metadata_json() -> *const c_char {
    let json = r#"{
  "manifest_version": 1,
  "module_api_version": 1,
  "runtime": "dynlib",
  "name": "auxiliary/test/dynlib_echo",
  "description": "Dynlib echo test module",
  "category": "auxiliary",
  "rank": "normal",
  "author": "moonlight",
  "platforms": ["cross"],
  "tags": ["test", "dynlib"],
  "entrypoint": "libmoonlight_dynlib_test"
}"#;
    CString::new(json).unwrap().into_raw()
}

extern "C" fn get_options_json() -> *const c_char {
    let json = r#"[
  {
    "name": "INPUT",
    "description": "Input text",
    "kind": "string",
    "required": true
  }
]"#;
    CString::new(json).unwrap().into_raw()
}

extern "C" fn create() -> *mut c_void {
    let state = ModuleState {
        input: String::new(),
    };
    Box::into_raw(Box::new(Mutex::new(state))) as *mut c_void
}

extern "C" fn destroy(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(ptr as *mut Mutex<ModuleState>);
    }
}

extern "C" fn set_option(ptr: *mut c_void, key: *const c_char, value: *const c_char) -> i32 {
    if ptr.is_null() || key.is_null() || value.is_null() {
        return -1;
    }
    let key = unsafe { CStr::from_ptr(key) }.to_string_lossy();
    let value = unsafe { CStr::from_ptr(value) }.to_string_lossy();
    let state = unsafe { &*(ptr as *mut Mutex<ModuleState>) };
    let mut guard = state.lock().unwrap();
    if key.eq_ignore_ascii_case("INPUT") {
        guard.input = value.to_string();
        0
    } else {
        -2
    }
}

extern "C" fn run(ptr: *mut c_void, _ctx: *const c_char) -> ModuleResultV1 {
    if ptr.is_null() {
        return ModuleResultV1 {
            success: 0,
            message: CString::new("null handle").unwrap().into_raw(),
        };
    }
    let state = unsafe { &*(ptr as *mut Mutex<ModuleState>) };
    let guard = state.lock().unwrap();
    let msg = format!("echo: {}", guard.input);
    ModuleResultV1 {
        success: 1,
        message: CString::new(msg).unwrap().into_raw(),
    }
}

extern "C" fn free_string(ptr: *const c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr as *mut c_char);
    }
}
