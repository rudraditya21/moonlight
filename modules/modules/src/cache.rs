use crate::hash::FileFingerprint;
use crate::metadata::ModuleMetadata;

#[derive(Debug, Clone)]
pub struct CachedEntry {
    pub manifest_path: String,
    pub fingerprint: FileFingerprint,
    pub metadata: ModuleMetadata,
}
