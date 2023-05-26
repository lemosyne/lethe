use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize, Deserialize)]
pub struct Allocator {
    latest: u64,
    allocated: HashSet<u64>,
}

impl Allocator {
    pub fn new() -> Self {
        Self {
            latest: 0,
            allocated: HashSet::new(),
        }
    }

    pub fn alloc(&mut self) -> Result<u64, Error> {
        let start = self.latest;
        let mut looped = false;

        while !(start == self.latest && looped) {
            if !self.allocated.contains(&self.latest) {
                self.allocated.insert(self.latest);
                return Ok(self.latest);
            }
            self.latest = self.latest.wrapping_add(1);
            looped = true;
        }

        Err(Error::ObjIdAllocation)
    }

    pub fn dealloc(&mut self, objid: u64) {
        self.allocated.remove(&objid);
    }
}
