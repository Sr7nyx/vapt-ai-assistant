"use client";

/**
 * Stale-while-revalidate cache with request de-duplication.
 *
 * Two problems it solves, both visible on the dashboard:
 *
 * Returning to a page you have already loaded should not show a spinner. The
 * cached value is returned immediately and a refresh runs behind it, so the page
 * is populated on arrival and correct a moment later.
 *
 * Two components asking for the same thing at the same moment should make one
 * request. The overview is read by both the dashboard and the persistent status
 * line; without de-duplication, landing on the dashboard issued the same
 * expensive query twice.
 *
 * In memory only, and cleared on sign-out: one user's aggregates must never be
 * served to the next account in the same browser.
 */

type Entry<T> = { value: T; at: number };

const store = new Map<string, Entry<unknown>>();
const inflight = new Map<string, Promise<unknown>>();

/** How long a cached value is served without a background refresh. */
const FRESH_MS = 15_000;

export function readCache<T>(key: string): T | undefined {
  return store.get(key)?.value as T | undefined;
}

export function clearCache(): void {
  store.clear();
  inflight.clear();
}

/**
 * Resolve `key`, sharing any request already in flight.
 *
 * `onValue` is called immediately with a cached value when one exists, and again
 * with the fresh value once it arrives, so a caller can render instantly and
 * update in place.
 */
export function swr<T>(
  key: string,
  fetcher: () => Promise<T>,
  onValue: (value: T, fromCache: boolean) => void
): () => void {
  let live = true;
  const cached = store.get(key) as Entry<T> | undefined;

  if (cached) onValue(cached.value, true);

  const fresh = cached && Date.now() - cached.at < FRESH_MS;
  if (fresh) return () => { live = false; };

  let request = inflight.get(key) as Promise<T> | undefined;
  if (!request) {
    request = fetcher()
      .then((value) => {
        store.set(key, { value, at: Date.now() });
        return value;
      })
      .finally(() => inflight.delete(key));
    inflight.set(key, request as Promise<unknown>);
  }

  request
    .then((value) => {
      if (live) onValue(value, false);
    })
    .catch(() => {
      // A failed refresh leaves any cached value in place: showing the last known
      // figures beats blanking the page because one poll did not land.
    });

  return () => {
    live = false;
  };
}

/** Drop a key so the next read refetches. Called after anything that changes the
 *  underlying data, so the dashboard cannot show stale counts after a commit. */
export function invalidate(prefix: string): void {
  for (const key of Array.from(store.keys())) {
    if (key.startsWith(prefix)) store.delete(key);
  }
}
