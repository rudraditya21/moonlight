use corelib::error::CoreResult;

pub trait Codec<T> {
    fn encode(&self, value: &T) -> CoreResult<Vec<u8>>;
    fn decode(&self, bytes: &[u8]) -> CoreResult<T>;
}
