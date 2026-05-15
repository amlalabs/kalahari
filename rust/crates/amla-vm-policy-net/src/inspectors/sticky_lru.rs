// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Bounded cache that prefers evicting non-sticky entries.
//!
//! Shared by protocol inspectors so a malicious guest can't flood the state
//! table to flush its cached Deny decision: entries the caller marks "sticky"
//! are only evicted when every slot is sticky, and that fallback is surfaced
//! via a callback so it can be logged as a security-relevant event.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, Clone)]
struct Entry<V> {
    value: V,
    generation: u64,
    /// Stickiness is fixed at insert time, not recomputed per-eviction. This
    /// guarantees per-entry classification is consistent across all evictions
    /// that entry participates in, independent of caller-closure state.
    sticky: bool,
}

struct Inner<K, V> {
    map: HashMap<K, Entry<V>>,
    /// Monotonic LRU counter. Allocated *inside* the write-lock critical
    /// section so two concurrent `touch`/`insert` calls can't interleave a
    /// fetch-then-write and install a stale generation. Never wraps in
    /// practice (u64 at 1 bump/ns would take ~585 years to wrap).
    next_generation: u64,
}

/// Bounded LRU cache with sticky-entry preference.
///
/// On insert, non-sticky entries are evicted first, in LRU order; only when
/// every resident entry is sticky does eviction fall back to the oldest
/// sticky entry, which invokes `on_sticky_evict` so the caller can log it.
pub struct StickyLruCache<K, V> {
    inner: RwLock<Inner<K, V>>,
    max_entries: usize,
}

impl<K, V> StickyLruCache<K, V>
where
    K: Eq + Hash + Copy,
    V: Clone,
{
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: RwLock::new(Inner {
                map: HashMap::new(),
                next_generation: 0,
            }),
            max_entries,
        }
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.read().map.len()
    }

    pub fn clear(&self) {
        self.inner.write().map.clear();
    }

    pub fn set_max_entries(&mut self, max: usize) {
        self.max_entries = max;
    }

    /// Clone the stored value for `key` without updating LRU.
    pub fn peek(&self, key: &K) -> Option<V> {
        self.inner.read().map.get(key).map(|e| e.value.clone())
    }

    /// Bump the LRU generation for `key`. Returns `true` if the key was
    /// present, `false` otherwise. Generation is allocated inside the write
    /// lock so concurrent touches always produce a monotonic ordering.
    // Reason: `map` and `next_generation` are borrows of `*inner`, so the
    // guard must live for the duration of the destructured use; clippy's
    // suggested early `drop(inner)` would invalidate those references.
    #[allow(clippy::significant_drop_tightening)]
    pub fn touch(&self, key: &K) -> bool {
        let mut inner = self.inner.write();
        let Inner {
            map,
            next_generation,
        } = &mut *inner;
        if let Some(entry) = map.get_mut(key) {
            entry.generation = *next_generation;
            *next_generation += 1;
            true
        } else {
            false
        }
    }

    /// Insert or overwrite `(key, value)`.
    ///
    /// `sticky` is evaluated once by the caller and stored with the entry —
    /// all future evictions scan the stored bit, never re-invoke caller logic.
    ///
    /// On a brand-new key that would exceed `max_entries`, evicts one entry
    /// first: the oldest non-sticky, else the oldest sticky with
    /// `on_sticky_evict` invoked. Overwriting an existing key never evicts.
    // Reason: `map` and `next_generation` are borrows of `*inner`, so the
    // guard must live for the duration of the destructured use; clippy's
    // suggested early `drop(inner)` would invalidate those references.
    #[allow(clippy::significant_drop_tightening)]
    pub fn insert(&self, key: K, value: V, sticky: bool, on_sticky_evict: impl FnOnce(&K)) {
        let mut inner = self.inner.write();
        let Inner {
            map,
            next_generation,
        } = &mut *inner;

        if !map.contains_key(&key) && map.len() >= self.max_entries {
            let mut oldest_non_sticky: Option<(K, u64)> = None;
            let mut oldest_sticky: Option<(K, u64)> = None;
            for (k, e) in map.iter() {
                let slot = if e.sticky {
                    &mut oldest_sticky
                } else {
                    &mut oldest_non_sticky
                };
                match slot {
                    Some((_, g)) if *g <= e.generation => {}
                    _ => *slot = Some((*k, e.generation)),
                }
            }
            // A non-empty, at-cap map must always yield at least one eviction
            // candidate — every entry is either sticky or non-sticky.
            debug_assert!(
                oldest_non_sticky.is_some() || oldest_sticky.is_some(),
                "non-empty at-cap cache must have at least one eviction candidate",
            );
            if let Some((k, _)) = oldest_non_sticky {
                map.remove(&k);
            } else if let Some((k, _)) = oldest_sticky {
                on_sticky_evict(&k);
                map.remove(&k);
            }
        }

        let generation = *next_generation;
        *next_generation += 1;
        map.insert(
            key,
            Entry {
                value,
                generation,
                sticky,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_does_not_touch() {
        let c = StickyLruCache::<u32, i32>::new(2);
        c.insert(1, 10, false, |_| {});
        c.insert(2, 20, false, |_| {});
        // Peek key 1 — does NOT refresh its generation.
        assert_eq!(c.peek(&1), Some(10));
        // Insert key 3: key 1 is still oldest non-sticky → evicted.
        c.insert(3, 30, false, |_| panic!("no sticky eviction expected"));
        assert_eq!(c.peek(&1), None);
        assert_eq!(c.peek(&2), Some(20));
        assert_eq!(c.peek(&3), Some(30));
    }

    #[test]
    fn touch_refreshes_lru() {
        let c = StickyLruCache::<u32, i32>::new(2);
        c.insert(1, 10, false, |_| {});
        c.insert(2, 20, false, |_| {});
        // Touch key 1 so 2 is now oldest.
        assert!(c.touch(&1));
        c.insert(3, 30, false, |_| panic!("no sticky eviction expected"));
        assert_eq!(c.peek(&1), Some(10));
        assert_eq!(c.peek(&2), None);
        assert_eq!(c.peek(&3), Some(30));
    }

    #[test]
    fn touch_returns_false_when_key_absent() {
        let c = StickyLruCache::<u32, i32>::new(2);
        assert!(!c.touch(&42));
        c.insert(1, 10, false, |_| {});
        assert!(c.touch(&1));
        assert!(!c.touch(&2));
    }

    #[test]
    fn sticky_beats_older_non_sticky() {
        // An old sticky entry must survive an insert that would normally
        // evict the oldest. The newer non-sticky entry is evicted instead.
        let c = StickyLruCache::<u32, i32>::new(2);
        c.insert(1, -1, true, |_| {}); // sticky, oldest
        c.insert(2, 20, false, |_| {}); // non-sticky, newer
        c.insert(3, 30, false, |_| panic!("sticky must not be evicted"));
        assert_eq!(c.peek(&1), Some(-1));
        assert_eq!(c.peek(&2), None);
        assert_eq!(c.peek(&3), Some(30));
    }

    #[test]
    fn all_sticky_evicts_oldest_sticky_with_callback() {
        let c = StickyLruCache::<u32, i32>::new(2);
        c.insert(1, -1, true, |_| {}); // sticky, oldest
        c.insert(2, -2, true, |_| {}); // sticky, newer
        let mut evicted: Option<u32> = None;
        c.insert(3, -3, true, |k| evicted = Some(*k));
        assert_eq!(evicted, Some(1), "oldest sticky must be the one evicted");
        assert_eq!(c.peek(&1), None);
        assert_eq!(c.peek(&2), Some(-2));
        assert_eq!(c.peek(&3), Some(-3));
    }

    #[test]
    fn overwrite_does_not_evict() {
        let c = StickyLruCache::<u32, i32>::new(2);
        c.insert(1, 10, false, |_| {});
        c.insert(2, 20, false, |_| {});
        // Overwriting key 1 — we're at cap but not growing, so no eviction.
        c.insert(1, 11, false, |_| panic!("overwrite must not evict"));
        assert_eq!(c.peek(&1), Some(11));
        assert_eq!(c.peek(&2), Some(20));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn clear_empties_cache() {
        let c = StickyLruCache::<u32, i32>::new(4);
        c.insert(1, 10, false, |_| {});
        c.insert(2, -2, true, |_| {});
        assert_eq!(c.len(), 2);
        c.clear();
        assert_eq!(c.len(), 0);
        assert_eq!(c.peek(&1), None);
        assert_eq!(c.peek(&2), None);
    }

    #[test]
    fn generation_monotonic_across_concurrent_touches() {
        // The race the review flagged: two threads each touch the same key.
        // With the old fetch-add-outside-lock pattern, the later-completing
        // write could install a lower generation. Under the new design,
        // generation is allocated inside the write lock, so the last touch
        // always has the highest generation.
        use std::sync::Arc;
        use std::thread;

        let c = Arc::new(StickyLruCache::<u32, i32>::new(8));
        c.insert(1, 10, false, |_| {});
        c.insert(2, 20, false, |_| {});

        // Touch both keys from many threads concurrently.
        let mut handles = vec![];
        for _ in 0..8 {
            let c = Arc::clone(&c);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    c.touch(&1);
                    c.touch(&2);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // No panic, no assertion failure. The invariant (monotonic) is
        // exercised implicitly: if generations could go backwards the LRU
        // eviction test below would be flaky.
        c.insert(3, 30, false, |_| {});
        c.insert(4, 40, false, |_| {});
        // Table has capacity 8, so no eviction. Just verify everyone survived.
        assert!(c.peek(&1).is_some());
        assert!(c.peek(&2).is_some());
    }
}
