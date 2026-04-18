// @wyella/jwt-verify — NextAuth v4 JWE decode + request verification.
// Decrypts session tokens minted by wyella-site against the same
// NEXTAUTH_SECRET, then enforces OPE-168 header overrides in the shape
// ported from wyella/identity/lib/auth-middleware.ts — no DB, no node
// crypto. Runs in the Next.js Edge runtime.

import { compactDecrypt } from 'jose';
import {
  JwtVerifyError, type TokenPayload, type VerifyOptions,
  type EffectiveContext,
} from './types';

export type {
  TokenPayload, VerifyOptions, MiddlewareOptions, EffectiveContext,
  VerifyErrorCode,
} from './types';
export { JwtVerifyError } from './types';
export { createJwtMiddleware } from './middleware';

const HKDF_INFO = 'NextAuth.js Generated Encryption Key';
const DEFAULT_MAX_AGE = 43200;
const SECURE_COOKIE = '__Secure-next-auth.session-token';
const DEV_COOKIE = 'next-auth.session-token';
const keyCache = new Map<string, Promise<Uint8Array>>();

async function deriveKey(secret: string): Promise<Uint8Array> {
  const cached = keyCache.get(secret); if (cached) return cached;
  const p = (async () => {
    const base = await crypto.subtle.importKey('raw',
      new TextEncoder().encode(secret), 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(HKDF_INFO),
    }, base, 256);
    return new Uint8Array(bits);
  })();
  keyCache.set(secret, p); return p;
}

function assertPayload(r: any): TokenPayload {
  if (!r || typeof r !== 'object') throw new JwtVerifyError('invalid_token', 'payload not object', 401);
  if (typeof r.userId !== 'string') throw new JwtVerifyError('invalid_token', 'missing userId', 401);
  if (typeof r.customerId !== 'string') throw new JwtVerifyError('invalid_token', 'missing customerId (pre-OPE-168?)', 401);
  if (!Array.isArray(r.customerIds)) throw new JwtVerifyError('invalid_token', 'missing customerIds', 401);
  if (!Array.isArray(r.siteIds)) throw new JwtVerifyError('invalid_token', 'missing siteIds', 401);
  if (typeof r.role !== 'string') throw new JwtVerifyError('invalid_token', 'missing role', 401);
  if (!Array.isArray(r.capabilities)) throw new JwtVerifyError('invalid_token', 'missing capabilities', 401);
  return {
    userId: r.userId, email: typeof r.email === 'string' ? r.email : undefined,
    isSystemAdmin: r.isSystemAdmin === true,
    customerId: r.customerId, customerIds: r.customerIds,
    siteId: typeof r.siteId === 'string' ? r.siteId : null, siteIds: r.siteIds,
    role: r.role, roleLabel: typeof r.roleLabel === 'string' ? r.roleLabel : r.role,
    capabilities: r.capabilities,
    iat: typeof r.iat === 'number' ? r.iat : undefined,
    exp: typeof r.exp === 'number' ? r.exp : undefined,
    sub: typeof r.sub === 'string' ? r.sub : undefined,
    name: typeof r.name === 'string' ? r.name : undefined,
  };
}

export async function verifyJwt(token: string, opts: VerifyOptions): Promise<TokenPayload> {
  if (!token) throw new JwtVerifyError('no_token', 'token empty', 401);
  const key = await deriveKey(opts.secret);
  let plaintext: Uint8Array;
  try { plaintext = (await compactDecrypt(token, key)).plaintext; }
  catch (e) { throw new JwtVerifyError('invalid_token', `JWE decrypt failed: ${(e as Error).message}`, 401); }
  const p = assertPayload(JSON.parse(new TextDecoder().decode(plaintext)));
  const now = Math.floor(Date.now() / 1000);
  if (typeof p.exp === 'number' && p.exp < now) throw new JwtVerifyError('expired_token', 'token expired (exp)', 401);
  const max = opts.maxAgeSeconds ?? DEFAULT_MAX_AGE;
  if (typeof p.iat === 'number' && p.iat + max < now) throw new JwtVerifyError('expired_token', 'token exceeds maxAge', 401);
  return p;
}

type ReqLike = { headers: Headers | Record<string, string | string[] | undefined> };

function getHeader(h: ReqLike['headers'], name: string): string | null {
  if (typeof (h as Headers).get === 'function') return (h as Headers).get(name);
  const d = h as Record<string, string | string[] | undefined>;
  const raw = d[name] ?? d[name.toLowerCase()];
  if (!raw) return null;
  const v = Array.isArray(raw) ? raw[0] : raw;
  return v.trim() || null;
}

export function cookieReader(req: ReqLike, cookieName?: string): string | null {
  const raw = getHeader(req.headers, 'cookie');
  if (!raw) return null;
  const map: Record<string, string> = {};
  for (const p of raw.split(';')) {
    const i = p.indexOf('='); if (i < 0) continue;
    const k = p.slice(0, i).trim(); if (!k) continue;
    map[k] = decodeURIComponent(p.slice(i + 1).trim());
  }
  if (cookieName && map[cookieName]) return map[cookieName];
  return map[SECURE_COOKIE] || map[DEV_COOKIE] || null;
}

// Ports withAuth() header-override enforcement from
// wyella/identity/lib/auth-middleware.ts, minus the DB re-resolution of
// sysadmin cross-customer sites — consumer apps trust JWT.siteIds.
export async function verifyRequest(
  req: ReqLike,
  opts: VerifyOptions & { capability?: string | null }
): Promise<{ payload: TokenPayload; effective: EffectiveContext }> {
  const token = cookieReader(req, opts.cookieName);
  if (!token) throw new JwtVerifyError('no_token', 'session cookie absent', 401);
  const payload = await verifyJwt(token, opts);

  const customerOverride = getHeader(req.headers, 'x-wyella-customer-id');
  const siteOverride = getHeader(req.headers, 'x-wyella-site-id');

  let customerCode = payload.customerId;
  if (customerOverride) {
    const ok = payload.customerIds.includes('*') ||
      payload.customerIds.some(c => c.toUpperCase() === customerOverride.toUpperCase());
    if (!ok) throw new JwtVerifyError('customer_not_accessible', `customer ${customerOverride} not in JWT`, 403);
    customerCode = customerOverride.toUpperCase();
  }

  let siteName = payload.siteId;
  if (siteOverride) {
    const match = payload.siteIds.find(s => s.toUpperCase() === siteOverride.toUpperCase());
    if (!match) throw new JwtVerifyError('site_not_accessible', `site ${siteOverride} not in JWT`, 403);
    siteName = match;
  }

  const cap = opts.capability;
  if (cap && !payload.isSystemAdmin && !payload.capabilities.includes(cap)) {
    throw new JwtVerifyError('capability_denied', `capability ${cap} not granted`, 403);
  }

  return {
    payload,
    effective: {
      userId: payload.userId, customerCode, siteName,
      role: payload.role, isSystemAdmin: payload.isSystemAdmin,
    },
  };
}
