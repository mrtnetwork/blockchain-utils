//! Faithful Rust port of `LegacyPdqsort` (itself a port of Rust 1.56.1
//! `core::slice::sort` as copied by `halo2_legacy_pdqsort`, 64-bit behaviour).
//! UNSTABLE sort: equal-key permutation depends on every algorithmic detail,
//! so nothing here may be "simplified". No `assert!`; bounds are upheld by
//! construction (indices derived from lengths).

pub fn quicksort<T: Clone>(v: &mut [T], is_less: &dyn Fn(&T, &T) -> bool) {
    let limit = bit_length(v.len());
    recurse(v, 0, v.len(), is_less, None, limit);
}

fn bit_length(mut n: usize) -> u32 {
    let mut b = 0u32;
    while n > 0 {
        b += 1;
        n >>= 1;
    }
    b
}

fn swap<T>(v: &mut [T], i: usize, j: usize) {
    if i != j {
        v.swap(i, j);
    }
}

fn shift_head<T: Clone>(v: &mut [T], lo: usize, hi: usize, is_less: &dyn Fn(&T, &T) -> bool) {
    let len = hi - lo;
    if len >= 2 && is_less(&v[lo + 1], &v[lo]) {
        let tmp = v[lo].clone();
        v[lo] = v[lo + 1].clone();
        let mut hole = lo + 1;
        let mut i = lo + 2;
        while i < hi {
            if !is_less(&v[i], &tmp) {
                break;
            }
            v[i - 1] = v[i].clone();
            hole = i;
            i += 1;
        }
        v[hole] = tmp;
    }
}

fn shift_tail<T: Clone>(v: &mut [T], lo: usize, hi: usize, is_less: &dyn Fn(&T, &T) -> bool) {
    let len = hi - lo;
    if len >= 2 && is_less(&v[hi - 1], &v[hi - 2]) {
        let tmp = v[hi - 1].clone();
        v[hi - 1] = v[hi - 2].clone();
        let mut hole = hi - 2;
        let mut i = hi as isize - 3;
        while i >= lo as isize {
            if !is_less(&tmp, &v[i as usize]) {
                break;
            }
            v[i as usize + 1] = v[i as usize].clone();
            hole = i as usize;
            i -= 1;
        }
        v[hole] = tmp;
    }
}

fn partial_insertion_sort<T: Clone>(
    v: &mut [T],
    lo: usize,
    hi: usize,
    is_less: &dyn Fn(&T, &T) -> bool,
) -> bool {
    const MAX_STEPS: usize = 5;
    const SHORTEST_SHIFTING: usize = 50;
    let len = hi - lo;
    let mut i = 1usize;
    for _ in 0..MAX_STEPS {
        while i < len && !is_less(&v[lo + i], &v[lo + i - 1]) {
            i += 1;
        }
        if i == len {
            return true;
        }
        if len < SHORTEST_SHIFTING {
            return false;
        }
        swap(v, lo + i - 1, lo + i);
        shift_tail(v, lo, lo + i, is_less);
        shift_head(v, lo + i, hi, is_less);
    }
    false
}

fn insertion_sort<T: Clone>(v: &mut [T], lo: usize, hi: usize, is_less: &dyn Fn(&T, &T) -> bool) {
    let len = hi - lo;
    for i in 1..len {
        shift_tail(v, lo, lo + i + 1, is_less);
    }
}

fn heapsort<T: Clone>(v: &mut [T], lo: usize, hi: usize, is_less: &dyn Fn(&T, &T) -> bool) {
    fn sift_down<T: Clone>(
        v: &mut [T],
        lo: usize,
        end: usize,
        mut node: usize,
        is_less: &dyn Fn(&T, &T) -> bool,
    ) {
        loop {
            let left = 2 * node + 1;
            let right = 2 * node + 2;
            let greater = if right < end && is_less(&v[lo + left], &v[lo + right]) {
                right
            } else {
                left
            };
            if greater >= end || !is_less(&v[lo + node], &v[lo + greater]) {
                break;
            }
            swap(v, lo + node, lo + greater);
            node = greater;
        }
    }
    let len = hi - lo;
    let mut i = len / 2;
    while i > 0 {
        i -= 1;
        sift_down(v, lo, len, i, is_less);
    }
    for i in (1..len).rev() {
        swap(v, lo, lo + i);
        sift_down(v, lo, i, 0, is_less);
    }
}

fn partition_in_blocks<T: Clone>(
    v: &mut [T],
    lo: usize,
    hi: usize,
    pivot: &T,
    is_less: &dyn Fn(&T, &T) -> bool,
) -> usize {
    const BLOCK: usize = 128;
    let mut l = lo;
    let mut block_l = BLOCK;
    let mut start_l = 0usize;
    let mut end_l = 0usize;
    let mut offsets_l = [0usize; BLOCK];
    let mut r = hi;
    let mut block_r = BLOCK;
    let mut start_r = 0usize;
    let mut end_r = 0usize;
    let mut offsets_r = [0usize; BLOCK];

    loop {
        let is_done = (r - l) <= 2 * BLOCK;
        if is_done {
            let mut rem = r - l;
            if start_l < end_l || start_r < end_r {
                rem -= BLOCK;
            }
            if start_l < end_l {
                block_r = rem;
            } else if start_r < end_r {
                block_l = rem;
            } else {
                block_l = rem / 2;
                block_r = rem - block_l;
            }
        }
        if start_l == end_l {
            start_l = 0;
            end_l = 0;
            for (elem, i) in (l..).zip(0..block_l) {
                offsets_l[end_l] = i;
                if !is_less(&v[elem], pivot) {
                    end_l += 1;
                }
            }
        }
        if start_r == end_r {
            start_r = 0;
            end_r = 0;
            let mut elem = r;
            for i in 0..block_r {
                elem -= 1;
                offsets_r[end_r] = i;
                if is_less(&v[elem], pivot) {
                    end_r += 1;
                }
            }
        }
        let count = core::cmp::min(end_l - start_l, end_r - start_r);
        if count > 0 {
            // Cyclic permutation (matches Rust exactly).
            let left0 = l + offsets_l[start_l];
            let right0 = r - offsets_r[start_r] - 1;
            let tmp = v[left0].clone();
            v[left0] = v[right0].clone();
            for _ in 1..count {
                start_l += 1;
                let left = l + offsets_l[start_l];
                let right = r - offsets_r[start_r] - 1;
                v[right] = v[left].clone();
                start_r += 1;
                let left2 = l + offsets_l[start_l];
                let right2 = r - offsets_r[start_r] - 1;
                v[left2] = v[right2].clone();
            }
            let rightf = r - offsets_r[start_r] - 1;
            v[rightf] = tmp;
            start_l += 1;
            start_r += 1;
        }
        if start_l == end_l {
            l += block_l;
        }
        if start_r == end_r {
            r -= block_r;
        }
        if is_done {
            break;
        }
    }
    if start_l < end_l {
        while start_l < end_l {
            end_l -= 1;
            let a = l + offsets_l[end_l];
            r -= 1;
            swap(v, a, r);
        }
        r - lo
    } else if start_r < end_r {
        while start_r < end_r {
            end_r -= 1;
            let b = r - offsets_r[end_r] - 1;
            swap(v, l, b);
            l += 1;
        }
        l - lo
    } else {
        l - lo
    }
}

fn partition<T: Clone>(
    v: &mut [T],
    lo: usize,
    hi: usize,
    pivot_idx: usize,
    is_less: &dyn Fn(&T, &T) -> bool,
) -> (usize, bool) {
    swap(v, lo, lo + pivot_idx);
    let pivot = v[lo].clone();
    let base = lo + 1;
    let mut l = 0usize;
    let mut r = hi - base;
    while l < r && is_less(&v[base + l], &pivot) {
        l += 1;
    }
    while l < r && !is_less(&v[base + r - 1], &pivot) {
        r -= 1;
    }
    let mid = l + partition_in_blocks(v, base + l, base + r, &pivot, is_less);
    let was_partitioned = l >= r;
    swap(v, lo, lo + mid);
    (mid, was_partitioned)
}

fn partition_equal<T: Clone>(
    v: &mut [T],
    lo: usize,
    hi: usize,
    pivot_idx: usize,
    is_less: &dyn Fn(&T, &T) -> bool,
) -> usize {
    swap(v, lo, lo + pivot_idx);
    let pivot = v[lo].clone();
    let base = lo + 1;
    let mut l = 0usize;
    let mut r = hi - base;
    loop {
        while l < r && !is_less(&pivot, &v[base + l]) {
            l += 1;
        }
        while l < r && is_less(&pivot, &v[base + r - 1]) {
            r -= 1;
        }
        if l >= r {
            break;
        }
        r -= 1;
        swap(v, base + l, base + r);
        l += 1;
    }
    l + 1
}

fn break_patterns<T: Clone>(v: &mut [T], lo: usize, hi: usize) {
    let len = hi - lo;
    if len >= 8 {
        const MASK32: u64 = 0xffff_ffff;
        let mut random = (len as u64) & MASK32;
        let mut gen_u32 = || {
            random ^= (random << 13) & MASK32;
            random ^= random >> 17;
            random ^= (random << 5) & MASK32;
            random
        };
        let mut gen_usize_low = || {
            gen_u32();
            gen_u32()
        };
        let mut modulus: usize = 1;
        while modulus < len {
            modulus <<= 1;
        }
        let pos = len / 4 * 2;
        for i in 0..3 {
            let mut other = (gen_usize_low() as usize) & (modulus - 1);
            if other >= len {
                other -= len;
            }
            swap(v, lo + pos - 1 + i, lo + other);
        }
    }
}

fn choose_pivot<T: Clone>(
    v: &mut [T],
    lo: usize,
    hi: usize,
    is_less: &dyn Fn(&T, &T) -> bool,
) -> (usize, bool) {
    const SHORTEST_MEDIAN_OF_MEDIANS: usize = 50;
    const MAX_SWAPS: usize = 12;
    let len = hi - lo;
    // Ref: [len ~/ 4 * 1, len ~/ 4 * 2, len ~/ 4 * 3] — `(len~/4)*k`, NOT len~/k.
    let mut abc = [len / 4, (len / 4) * 2, (len / 4) * 3];
    let mut swaps = 0usize;
    if len >= 8 {
        // sort2/sort3 over index triples with swap counting.
        fn sort2<T: Clone>(
            v: &mut [T],
            lo: usize,
            p: &mut [usize; 3],
            i: usize,
            j: usize,
            swaps: &mut usize,
            is_less: &dyn Fn(&T, &T) -> bool,
        ) {
            if is_less(&v[lo + p[j]], &v[lo + p[i]]) {
                p.swap(i, j);
                *swaps += 1;
            }
        }
        // Inline sort3 calls (borrows prevent a closure capturing v mutably
        // alongside p, so the steps are spelled out).
        if len >= SHORTEST_MEDIAN_OF_MEDIANS {
            for slot in abc.iter_mut() {
                let tmp = *slot;
                let mut t = [tmp - 1, tmp, tmp + 1];
                sort2(v, lo, &mut t, 0, 1, &mut swaps, is_less);
                sort2(v, lo, &mut t, 1, 2, &mut swaps, is_less);
                sort2(v, lo, &mut t, 0, 1, &mut swaps, is_less);
                *slot = t[1];
            }
        }
        sort2(v, lo, &mut abc, 0, 1, &mut swaps, is_less);
        sort2(v, lo, &mut abc, 1, 2, &mut swaps, is_less);
        sort2(v, lo, &mut abc, 0, 1, &mut swaps, is_less);
    }
    let b = abc[1];
    if swaps < MAX_SWAPS {
        (b, swaps == 0)
    } else {
        let mut i = lo;
        let mut j = hi - 1;
        while i < j {
            swap(v, i, j);
            i += 1;
            j -= 1;
        }
        (len - 1 - b, true)
    }
}

fn recurse<T: Clone>(
    v: &mut [T],
    mut lo: usize,
    mut hi: usize,
    is_less: &dyn Fn(&T, &T) -> bool,
    mut pred: Option<T>,
    mut limit: u32,
) {
    const MAX_INSERTION: usize = 20;
    let mut was_balanced = true;
    let mut was_partitioned = true;
    loop {
        let len = hi - lo;
        if len <= MAX_INSERTION {
            insertion_sort(v, lo, hi, is_less);
            return;
        }
        if limit == 0 {
            heapsort(v, lo, hi, is_less);
            return;
        }
        if !was_balanced {
            break_patterns(v, lo, hi);
            limit -= 1;
        }
        let (pivot, likely_sorted) = choose_pivot(v, lo, hi, is_less);
        if was_balanced && was_partitioned && likely_sorted && partial_insertion_sort(v, lo, hi, is_less) {
            return;
        }
        if let Some(p) = &pred {
            if !is_less(p, &v[lo + pivot]) {
                let mid = partition_equal(v, lo, hi, pivot, is_less);
                lo += mid;
                continue;
            }
        }
        let (mid, was_p) = partition(v, lo, hi, pivot, is_less);
        let smaller = core::cmp::min(mid, len - mid);
        was_balanced = smaller >= len / 8;
        was_partitioned = was_p;
        let pivot_val = v[lo + mid].clone();
        let (left_lo, left_hi) = (lo, lo + mid);
        let (right_lo, right_hi) = (lo + mid + 1, hi);
        if left_hi - left_lo < right_hi - right_lo {
            recurse(v, left_lo, left_hi, is_less, pred, limit);
            lo = right_lo;
            hi = right_hi;
            pred = Some(pivot_val);
        } else {
            recurse(v, right_lo, right_hi, is_less, Some(pivot_val), limit);
            lo = left_lo;
            hi = left_hi;
        }
    }
}
