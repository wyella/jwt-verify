// Session revocation lookup — WS-H Phase 4 (v0.2.0).
//
// Edge runtime constraint: cannot use `pg` directly. Instead, the
// identity service exposes a thin endpoint at
// `${IDENTITY_URL}/api/auth/revocation?user_id=X` that returns the
// per-user revocation timestamp + global epoch from the
// `session_revocation` + `session_revocation_global` tables.
//
// This module:
// - fetches that endpoint with a short-TTL module-scope cache (default
//   30s per OPE-254; overridable via `revocationCacheMs` option)
// - decides on fail-open vs fail-closed via opts.failOpen (default
//   FALSE per OPE-254 default)
// - returns whether a given token is revoked by comparing JWT.iat
//   against the per-user revoked_at and the global epoch
//
// Per James's P6 decision (2026-04-26): DB-backed revocation; KV path
// dropped.

export interface RevocationStatus {
  /** Per-user revocation timestamp in epoch ms. null = no per-user revocation. */
  user_revoked_at: number | null;
  /** Global revocation epoch in epoch ms. 0 = unset (bootstrap). */
  global_epoch: number;
  /** True if the lookup failed and we returned a fail-open default. */
  fallback: boolean;
}

export interface RevocationOptions {
  /** Endpoint URL — typically https://identity.wyella.ca/api/auth/revocation */
  endpoint: string;
  /** Module-scope cache TTL in ms. Default 30_000 (30s). */
  cacheMs?: number;
  /** If true, treat fetch failures as not-revoked. Default false (fail-closed per OPE-254). */
  failOpen?: boolean;
  /** AbortSignal timeout in ms. Default 2_000. */
  timeoutMs?: number;
}

interface CacheEntry {
  value: RevocationStatus;
  expires: number;
}

const cache = new Map<string, CacheEntry>();

/** Clear the cache — useful for tests. */
export function _clearRevocationCache(): void {
  cache.clear();
}

const DEFAULT_CACHE_MS = 30_000;
const DEFAULT_TIMEOUT_MS = 2_000;
const FAIL_FAST_NEGATIVE_CACHE_MS = 1_000; // re-try quickly after a failure

export async function checkRevocation(
  userId: string,
  opts: RevocationOptions
): Promise<RevocationStatus> {
  if (!userId) {
    return { user_revoked_at: null, global_epoch: 0, fallback: true };
  }

  const now = Date.now();
  const cached = cache.get(userId);
  if (cached && cached.expires > now) return cached.value;

  const cacheMs = opts.cacheMs ?? DEFAULT_CACHE_MS;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const url = `${opts.endpoint}?user_id=${encodeURIComponent(userId)}`;

  try {
    const res = await fetch(url, {
      cache: 'no-store',
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) {
      throw new Error(`revocation endpoint ${res.status}`);
    }
    const data = (await res.json()) as { revoked_at: string | null; global_epoch: string };
    const value: RevocationStatus = {
      user_revoked_at: data.revoked_at ? Date.parse(data.revoked_at) : null,
      global_epoch: data.global_epoch ? Date.parse(data.global_epoch) : 0,
      fallback: false,
    };
    cache.set(userId, { value, expires: now + cacheMs });
    return value;
  } catch {
    if (opts.failOpen) {
      const v: RevocationStatus = { user_revoked_at: null, global_epoch: 0, fallback: true };
      cache.set(userId, { value: v, expires: now + FAIL_FAST_NEGATIVE_CACHE_MS });
      return v;
    }
    // Fail-closed (OPE-254 default): treat failure as "everything revoked
    // since 0", which forces the middleware to reject. Short cache so we
    // re-try quickly when identity recovers.
    const v: RevocationStatus = {
      user_revoked_at: null,
      global_epoch: Number.MAX_SAFE_INTEGER, // any iat < this → revoked
      fallback: true,
    };
    cache.set(userId, { value: v, expires: now + FAIL_FAST_NEGATIVE_CACHE_MS });
    return v;
  }
}

/**
 * Check whether a token (by iat) is revoked given the lookup result.
 * Comparison is in epoch ms; JWT iat is in seconds.
 */
export function isTokenRevoked(
  payload: { userId: string; iat?: number },
  status: RevocationStatus
): boolean {
  if (typeof payload.iat !== 'number') {
    // No iat means we can't tell; trust the per-user check only.
    return status.user_revoked_at != null;
  }
  const iatMs = payload.iat * 1000;
  if (status.user_revoked_at != null && status.user_revoked_at >= iatMs) return true;
  if (status.global_epoch > 0 && status.global_epoch >= iatMs) return true;
  return false;
}
