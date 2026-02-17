use crate::metadata::ModuleMetadata;
use crate::options::ModuleOptions;

#[derive(Debug, Clone)]
pub struct ModuleContext {
    pub session_id: u64,
}

pub trait ModuleSession: Send {
    fn kind(&self) -> &'static str;
    fn target(&self) -> String;
    fn is_open(&self) -> bool;
    fn write(&mut self, input: &[u8]) -> Result<(), ModuleError>;
    fn read(&mut self) -> Result<Vec<u8>, ModuleError>;
    fn close(&mut self) -> Result<(), ModuleError>;
}

pub struct ModuleResult {
    pub success: bool,
    pub message: String,
    pub session: Option<Box<dyn ModuleSession>>,
}

impl std::fmt::Debug for ModuleResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleResult")
            .field("success", &self.success)
            .field("message", &self.message)
            .field("session", &self.session.is_some())
            .finish()
    }
}

impl ModuleResult {
    pub fn ok(message: &str) -> Self {
        ModuleResult {
            success: true,
            message: message.to_string(),
            session: None,
        }
    }

    pub fn err(message: &str) -> Self {
        ModuleResult {
            success: false,
            message: message.to_string(),
            session: None,
        }
    }

    pub fn with_session(mut self, session: Box<dyn ModuleSession>) -> Self {
        self.session = Some(session);
        self
    }

    pub fn take_session(&mut self) -> Option<Box<dyn ModuleSession>> {
        self.session.take()
    }
}

#[derive(Debug)]
pub enum ModuleError {
    Validation(String),
    Execution(String),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModuleError::Validation(msg) => write!(f, "validation error: {msg}"),
            ModuleError::Execution(msg) => write!(f, "execution error: {msg}"),
        }
    }
}

impl std::error::Error for ModuleError {}

pub trait Module: Send {
    fn metadata(&self) -> &ModuleMetadata;
    fn options(&self) -> &ModuleOptions;
    fn options_mut(&mut self) -> &mut ModuleOptions;
    fn run(&mut self, ctx: &ModuleContext) -> Result<ModuleResult, ModuleError>;
}

pub trait ModuleFactory: Send + Sync {
    fn metadata(&self) -> &ModuleMetadata;
    fn create(&self) -> Box<dyn Module>;
}

#[derive(Debug, Clone)]
pub struct ModuleBase {
    metadata: ModuleMetadata,
    options: ModuleOptions,
}

impl ModuleBase {
    pub fn new(metadata: ModuleMetadata, options: ModuleOptions) -> Self {
        ModuleBase { metadata, options }
    }

    pub fn metadata(&self) -> &ModuleMetadata {
        &self.metadata
    }

    pub fn options(&self) -> &ModuleOptions {
        &self.options
    }

    pub fn options_mut(&mut self) -> &mut ModuleOptions {
        &mut self.options
    }

    pub fn validate(&self) -> Result<(), ModuleError> {
        self.options.validate().map_err(ModuleError::Validation)
    }
}
