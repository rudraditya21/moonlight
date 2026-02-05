use std::fmt;

#[derive(Debug)]
pub enum CoreError {
    Io(std::io::Error),
    Parse(String),
    Message(String),
}

pub type CoreResult<T> = Result<T, CoreError>;

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::Io(err) => write!(f, "io error: {err}"),
            CoreError::Parse(msg) => write!(f, "parse error: {msg}"),
            CoreError::Message(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<std::io::Error> for CoreError {
    fn from(err: std::io::Error) -> Self {
        CoreError::Io(err)
    }
}
