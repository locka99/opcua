// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

use std::u32;

/// A simple handle factory for incrementing sequences of numbers.
#[derive(Debug, Clone, Serialize)]
pub struct Handle {
    next: u32,
    first: u32,
}

impl Handle {
    /// Creates a new handle factory, that starts with the supplied number
    pub fn new(first: u32) -> Handle {
        Handle { next: first, first }
    }

    /// Returns the next handle to be issued, internally incrementing each time so the handle
    /// is always different until it wraps back to the start.
    pub fn next(&mut self) -> u32 {
        let next = self.next;
        // Increment next
        if self.next == u32::MAX {
            self.next = self.first;
        } else {
            self.next += 1;
        }
        next
    }

    pub fn set_next(&mut self, next: u32) {
        self.next = next;
    }

    /// Resets the handle to its initial state
    pub fn reset(&mut self) {
        self.set_next(self.first);
    }
}

#[test]
fn handle_increment() {
    // Expect sequential handles
    let mut h = Handle::new(0);
    assert_eq!(h.next(), 0);
    assert_eq!(h.next(), 1);
    assert_eq!(h.next(), 2);
    let mut h = Handle::new(100);
    assert_eq!(h.next(), 100);
    assert_eq!(h.next(), 101);
}

#[test]
fn handle_wrap() {
    // Simulate wrapping around
    let mut h = Handle::new(u32::MAX - 2);
    assert_eq!(h.next(), u32::MAX - 2);
    assert_eq!(h.next(), u32::MAX - 1);
    assert_eq!(h.next(), u32::MAX);
    assert_eq!(h.next(), u32::MAX - 2);
}
