//! Zero-dependency thread fan-out for native prove paths.
//!
//! - With crate feature `multicore` on a native target: real OS threads via
//!   `std::thread::scope` (stable since Rust 1.63, safe API only).
//! - Otherwise (feature off, `no_std`, or `wasm32`): sequential fallback
//!   with identical results. wasm builds never reference thread APIs.
//!
//! Worker panics are never swallowed and never introduced here: a panicking
//! worker propagates via `resume_unwind` (same policy as rayon-based code).
//! All helpers are deterministic given deterministic closures.

#[cfg(all(feature = "multicore", not(target_arch = "wasm32")))]
mod imp {
    /// Logical worker count for chunking decisions.
    ///
    /// `HALO2_THREADS` (if set to a positive integer) caps the count —
    /// useful under container CPU limits, where `available_parallelism`
    /// otherwise reports host CPUs.
    pub fn num_threads() -> usize {
        let detected = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 64);
        if let Some(cap) = thread_cap() {
            detected.min(cap).max(1)
        } else {
            detected
        }
    }

    #[cfg(feature = "std")]
    fn thread_cap() -> Option<usize> {
        std::env::var("HALO2_THREADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v >= 1)
    }

    #[cfg(not(feature = "std"))]
    fn thread_cap() -> Option<usize> {
        None
    }

    /// Run two closures, possibly in parallel. `b` runs on the caller.
    pub fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        std::thread::scope(|s| {
            let ha = s.spawn(a);
            let rb = b();
            let ra = match ha.join() {
                Ok(v) => v,
                Err(e) => std::panic::resume_unwind(e),
            };
            (ra, rb)
        })
    }

    /// Scoped fan-out handle (wraps `std::thread::Scope`).
    pub struct Scope<'scope, 'env> {
        inner: &'scope std::thread::Scope<'scope, 'env>,
    }

    impl<'scope, 'env> Scope<'scope, 'env> {
        /// Spawn a task borrowing caller data. See [`scope`].
        pub fn spawn<F, R>(&self, f: F) -> std::thread::ScopedJoinHandle<'_, R>
        where
            F: FnOnce() -> R + Send + 'env,
            R: Send + 'env,
        {
            self.inner.spawn(f)
        }

        /// Block until `handle` finishes, propagating worker panics.
        pub fn join<R>(handle: std::thread::ScopedJoinHandle<'_, R>) -> R {
            match handle.join() {
                Ok(v) => v,
                Err(e) => std::panic::resume_unwind(e),
            }
        }
    }

    /// Run `f` with a scope for spawning caller-borrowing tasks.
    /// Lifetimes infer from `f`'s captures (same shape as `std::thread::scope`).
    pub fn scope<'env, F, R>(f: F) -> R
    where
        F: FnOnce(&Scope<'_, 'env>) -> R,
    {
        std::thread::scope(|s| f(&Scope { inner: s }))
    }
}

#[cfg(not(all(feature = "multicore", not(target_arch = "wasm32"))))]
mod imp {
    /// Single-threaded fallback: always 1.
    pub fn num_threads() -> usize {
        1
    }

    /// Sequential fallback: run `a`, then `b`.
    pub fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        (a(), b())
    }

    /// Sequential scope: `spawn` runs immediately, `join` unwraps directly.
    pub struct Scope<'env> {
        _marker: core::marker::PhantomData<&'env ()>,
    }

    /// Immediate (already-joined) handle for the sequential fallback.
    pub struct Joined<R> {
        value: Option<R>,
    }

    impl<'env> Scope<'env> {
        /// Run `f` immediately; the returned handle is already complete.
        pub fn spawn<F, R>(&'env self, f: F) -> Joined<R>
        where
            F: FnOnce() -> R + Send + 'env,
            R: Send + 'env,
        {
            Joined { value: Some(f()) }
        }

        /// Take the already-computed value.
        pub fn join<R>(handle: Joined<R>) -> R {
            // Only constructible via `spawn`, which always fills `value`.
            handle.value.expect("multicore sequential handle")
        }
    }

    /// Sequential fallback: single call, no threads.
    pub fn scope<'env, F, R>(f: F) -> R
    where
        F: FnOnce(&Scope<'env>) -> R,
    {
        f(&Scope {
            _marker: core::marker::PhantomData,
        })
    }
}

pub use imp::{join, num_threads, scope, Scope};

/// Sequential handle type (only exists without native threads).
#[cfg(not(all(feature = "multicore", not(target_arch = "wasm32"))))]
pub use imp::Joined;
