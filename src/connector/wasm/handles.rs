//! Integer handle tables for wasm (no raw pointers across JS).

use std::cell::RefCell;

thread_local! {
    static NEXT: RefCell<u32> = RefCell::new(1);
}

/// Allocate a fresh integer handle id (starts at 1).
pub fn alloc_id() -> u32 {
    NEXT.with(|n| {
        let mut v = n.borrow_mut();
        let id = *v;
        *v = v.wrapping_add(1).max(1);
        id
    })
}
