//! Merlin transcript + Strobe duplex FFI (opaque handles).

use alloc::boxed::Box;
use core::ptr;
use core::slice;

use crate::merlin::Transcript;
use crate::strobe::Strobe;

pub const BU_TR_OK: i32 = 0;
pub const BU_TR_ERR_NULL: i32 = 1;
pub const BU_TR_ERR_BUFFER: i32 = 2;

// ---------------------------------------------------------------------------
// Strobe
// ---------------------------------------------------------------------------

/// Opaque Strobe128 state.
pub struct BuStrobe {
    inner: Strobe,
}

/// Create Strobe128 with protocol label. Free with [`bu_strobe_free`].
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_strobe_new(protocol: *const u8, protocol_len: usize) -> *mut BuStrobe {
    if protocol_len > 0 && protocol.is_null() {
        return ptr::null_mut();
    }
    let label = if protocol_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(protocol, protocol_len) }
    };
    let s = BuStrobe {
        inner: Strobe::new_128(label),
    };
    Box::into_raw(Box::new(s))
}

/// Associated data. `meta != 0` → meta-AD.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_strobe_ad(
    ptr: *mut BuStrobe,
    meta: u8,
    data: *const u8,
    data_len: usize,
) -> i32 {
    if ptr.is_null() {
        return BU_TR_ERR_NULL;
    }
    if data_len > 0 && data.is_null() {
        return BU_TR_ERR_NULL;
    }
    let s = unsafe { &mut *ptr };
    let bytes = if data_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(data, data_len) }
    };
    s.inner.ad(meta != 0, bytes);
    BU_TR_OK
}

/// KEY operation (ratchet secret material in).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_strobe_key(
    ptr: *mut BuStrobe,
    data: *const u8,
    data_len: usize,
) -> i32 {
    if ptr.is_null() {
        return BU_TR_ERR_NULL;
    }
    if data_len > 0 && data.is_null() {
        return BU_TR_ERR_NULL;
    }
    let s = unsafe { &mut *ptr };
    let bytes = if data_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(data, data_len) }
    };
    s.inner.key(bytes);
    BU_TR_OK
}

/// PRF into `out` (`out_len` bytes).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_strobe_prf(ptr: *mut BuStrobe, out: *mut u8, out_len: usize) -> i32 {
    if ptr.is_null() || out.is_null() || out_len == 0 {
        return BU_TR_ERR_NULL;
    }
    let s = unsafe { &mut *ptr };
    let prf = s.inner.prf(out_len);
    if prf.len() != out_len {
        return BU_TR_ERR_BUFFER;
    }
    unsafe {
        slice::from_raw_parts_mut(out, out_len).copy_from_slice(&prf);
    }
    BU_TR_OK
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_strobe_free(ptr: *mut BuStrobe) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

// ---------------------------------------------------------------------------
// Merlin transcript
// ---------------------------------------------------------------------------

/// Opaque Merlin transcript.
pub struct BuMerlin {
    inner: Transcript,
}

/// New Merlin transcript with domain-separation label.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_merlin_new(label: *const u8, label_len: usize) -> *mut BuMerlin {
    if label_len > 0 && label.is_null() {
        return ptr::null_mut();
    }
    let lab = if label_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(label, label_len) }
    };
    Box::into_raw(Box::new(BuMerlin {
        inner: Transcript::new(lab),
    }))
}

/// `append_message(label, message)`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_merlin_append(
    ptr: *mut BuMerlin,
    label: *const u8,
    label_len: usize,
    msg: *const u8,
    msg_len: usize,
) -> i32 {
    if ptr.is_null() {
        return BU_TR_ERR_NULL;
    }
    if label_len > 0 && label.is_null() {
        return BU_TR_ERR_NULL;
    }
    if msg_len > 0 && msg.is_null() {
        return BU_TR_ERR_NULL;
    }
    let t = unsafe { &mut *ptr };
    let lab = if label_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(label, label_len) }
    };
    let message = if msg_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(msg, msg_len) }
    };
    t.inner.append_message(lab, message);
    BU_TR_OK
}

/// `challenge_bytes(label, out)`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_merlin_challenge(
    ptr: *mut BuMerlin,
    label: *const u8,
    label_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if ptr.is_null() || out.is_null() || out_len == 0 {
        return BU_TR_ERR_NULL;
    }
    if label_len > 0 && label.is_null() {
        return BU_TR_ERR_NULL;
    }
    let t = unsafe { &mut *ptr };
    let lab = if label_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(label, label_len) }
    };
    let out_s = unsafe { slice::from_raw_parts_mut(out, out_len) };
    t.inner.challenge_bytes(lab, out_s);
    BU_TR_OK
}

/// Clone transcript (for parallel verify path). Returns new handle.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_merlin_fork(ptr: *const BuMerlin) -> *mut BuMerlin {
    if ptr.is_null() {
        return ptr::null_mut();
    }
    let t = unsafe { &*ptr };
    Box::into_raw(Box::new(BuMerlin {
        inner: t.inner.fork(),
    }))
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_merlin_free(ptr: *mut BuMerlin) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merlin_deterministic() {
        let label = b"test-domain";
        let t1 = unsafe { bu_merlin_new(label.as_ptr(), label.len()) };
        let t2 = unsafe { bu_merlin_new(label.as_ptr(), label.len()) };
        assert!(!t1.is_null() && !t2.is_null());
        let msg = b"hello";
        let lab = b"msg";
        unsafe {
            bu_merlin_append(t1, lab.as_ptr(), lab.len(), msg.as_ptr(), msg.len());
            bu_merlin_append(t2, lab.as_ptr(), lab.len(), msg.as_ptr(), msg.len());
        }
        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];
        let cl = b"chal";
        unsafe {
            assert_eq!(
                bu_merlin_challenge(t1, cl.as_ptr(), cl.len(), c1.as_mut_ptr(), 32),
                BU_TR_OK
            );
            assert_eq!(
                bu_merlin_challenge(t2, cl.as_ptr(), cl.len(), c2.as_mut_ptr(), 32),
                BU_TR_OK
            );
            bu_merlin_free(t1);
            bu_merlin_free(t2);
        }
        assert_eq!(c1, c2);
    }

    #[test]
    fn strobe_prf() {
        let proto = b"Merlin v1.0";
        let s = unsafe { bu_strobe_new(proto.as_ptr(), proto.len()) };
        assert!(!s.is_null());
        let data = b"dom-sep";
        unsafe {
            bu_strobe_ad(s, 1, data.as_ptr(), data.len());
            bu_strobe_ad(s, 0, b"x".as_ptr(), 1);
        }
        let mut out = [0u8; 16];
        assert_eq!(unsafe { bu_strobe_prf(s, out.as_mut_ptr(), 16) }, BU_TR_OK);
        assert_ne!(out, [0u8; 16]);
        unsafe { bu_strobe_free(s) };
    }
}
