//! Resource limits of identification (F19 §4.1 "Bounded parsing").

use std::time::Duration;

/// Bounds applied to every identification. The defaults are the F19 §4.1
/// values; MIA lowers `max_file_size` from `registration.max_file_size_mib`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest file hashed and parsed (`file_too_large` beyond it).
    pub max_file_size: u64,
    /// Most bytes of headers, resources, notes or plist read for metadata.
    pub max_metadata_bytes: u64,
    /// Deepest nesting a parser follows (plist collections, JSON, resources).
    pub max_depth: usize,
    /// Wall-clock budget for all metadata parsing of one file.
    pub time_budget: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_size: 2 * 1024 * 1024 * 1024,
            max_metadata_bytes: 16 * 1024 * 1024,
            max_depth: 16,
            time_budget: Duration::from_secs(2),
        }
    }
}
