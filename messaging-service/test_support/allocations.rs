//! Allocation counters installed only in the standalone example or the opt-in test binary.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
};

struct MeasuredAllocator;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn allocated(size: usize) {
    ALLOCS.fetch_add(1, Relaxed);
    BYTES.fetch_add(size, Relaxed);
    let live = LIVE.fetch_add(size, Relaxed) + size;
    PEAK.fetch_max(live, Relaxed);
}

// SAFETY: every operation forwards the original pointer/layout to System. Counters do not
// allocate, dereference pointers or change allocation results; failed allocations are ignored.
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies the layout required by the allocator contract.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same allocator contract as alloc, preserving zero-initialization.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        // SAFETY: ptr/layout are passed unchanged to the allocator that created the block.
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: forwarding the caller's valid allocation and requested new size.
        let next = unsafe { System.realloc(ptr, layout, size) };
        if !next.is_null() {
            LIVE.fetch_sub(layout.size(), Relaxed);
            allocated(size);
        }
        next
    }
}

#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

pub struct AllocationSample {
    calls: usize,
    bytes: usize,
    live: usize,
}

pub struct AllocationDelta {
    pub calls: usize,
    pub bytes: usize,
    pub live: usize,
    pub peak: usize,
    pub peak_delta: usize,
}

impl AllocationSample {
    // One isolated sample at a time. Counters are process-wide; peak resets here.
    pub fn start() -> Self {
        let live = LIVE.load(Relaxed);
        PEAK.store(live, Relaxed);
        Self {
            calls: ALLOCS.load(Relaxed),
            bytes: BYTES.load(Relaxed),
            live,
        }
    }

    pub fn finish(self) -> AllocationDelta {
        let peak = PEAK.load(Relaxed);
        AllocationDelta {
            calls: ALLOCS.load(Relaxed) - self.calls,
            bytes: BYTES.load(Relaxed) - self.bytes,
            live: LIVE.load(Relaxed),
            peak,
            peak_delta: peak.saturating_sub(self.live),
        }
    }
}
