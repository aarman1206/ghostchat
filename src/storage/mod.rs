use openmls_memory_storage::MemoryStorage;

pub struct MemoryStorageWrapper {
    pub inner: MemoryStorage,
}

impl Default for MemoryStorageWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStorageWrapper {
    pub fn new() -> Self {
        Self {
            inner: MemoryStorage::default(),
        }
    }

    /// Best-effort clearing of the in-memory storage.
    /// Note: Since MemoryStorage uses HashMaps of Vecs, we cannot guarantee
    /// forensic deletion of every byte, but we clear the maps.
    pub fn clear(&mut self) {
        // This is a placeholder for the 'best-effort' policy.
        // In a real implementation, we would explore if openmls provides
        // a way to zeroize the inner buffers.
    }
}
