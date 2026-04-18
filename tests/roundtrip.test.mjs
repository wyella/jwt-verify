// Unit tests for @wyella/jwt-verify. Mint a JWE with the same HKDF+A256GCM
// scheme NextAuth v4 uses and round-trip it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CompactEncrypt } from 'jose';
import { verifyJwt, verifyRequest, cookieReader, JwtVerifyError } from '../dist/index.js';

const SECRET = 'test-secret-only-for-unit-tests';
const HKDF_INFO = 'NextAuth.js Generated Encryption Key';

async function key(s = SECRET) {
  const b = await crypto.subtle.importKey('raw', new TextEncoder().encode(s),
    'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256',
    salt: new Uint8Array(0), info: new TextEncoder().encode(HKDF_INFO),
  }, b, 256);
  return new Uint8Array(bits);
}

async function mint(claims, secret = SECRET) {
  const now = Math.floor(Date.now() / 1000);
  return new CompactEncrypt(new TextEncoder().encode(
    JSON.stringify({ iat: now, exp: now + 3600, ...claims })
  )).setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }).encrypt(await key(secret));
}

const JIN = {
  userId: 'bc7e285d-9d50-4538-aa77-c94246e89477', email: 'jin.park@lngco.com',
  isSystemAdmin: false, customerId: 'LNGCO', customerIds: ['LNGCO'],
  siteId: 'LNG-DEMO', siteIds: ['LNG-DEMO'],
  role: 'supervisor', roleLabel: 'Shift Supervisor',
  capabilities: ['hsse', 'maint', 'opil', 'ptw'],
};
const SYS = { ...JIN, isSystemAdmin: true, customerId: 'WYELLA',
  customerIds: ['*'], siteId: null, siteIds: [], role: 'system_admin' };

test('verifyJwt round-trip — LNGCo v2 claims', async () => {
  const p = await verifyJwt(await mint(JIN), { secret: SECRET });
  assert.equal(p.userId, JIN.userId); assert.equal(p.customerId, 'LNGCO');
  assert.deepEqual(p.customerIds, ['LNGCO']); assert.equal(p.siteId, 'LNG-DEMO');
});

test('verifyJwt — sysadmin wildcard', async () => {
  const p = await verifyJwt(await mint(SYS), { secret: SECRET });
  assert.equal(p.isSystemAdmin, true); assert.deepEqual(p.customerIds, ['*']);
});

test('verifyJwt — wrong secret rejected', async () => {
  await assert.rejects(async () => verifyJwt(await mint(JIN), { secret: 'other' }),
    e => e instanceof JwtVerifyError && e.code === 'invalid_token');
});

test('verifyJwt — pre-OPE-168 token rejected', async () => {
  await assert.rejects(
    async () => verifyJwt(await mint({ userId: 'x', role: 'r', siteId: 's' }), { secret: SECRET }),
    e => e instanceof JwtVerifyError && e.code === 'invalid_token');
});

test('verifyJwt — expired rejected', async () => {
  const old = Math.floor(Date.now() / 1000) - 10000;
  const k = await key();
  const t = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(
    { ...JIN, iat: old, exp: old + 60 }
  ))).setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }).encrypt(k);
  await assert.rejects(() => verifyJwt(t, { secret: SECRET }),
    e => e instanceof JwtVerifyError && e.code === 'expired_token');
});

test('cookieReader prefers __Secure- prefix', () => {
  assert.equal(cookieReader({ headers: {
    cookie: 'next-auth.session-token=d; __Secure-next-auth.session-token=s',
  }}), 's');
});

test('cookieReader falls back to dev cookie', () => {
  assert.equal(cookieReader({ headers: { cookie: 'next-auth.session-token=d' } }), 'd');
});

test('cookieReader accepts Headers instance', () => {
  assert.equal(cookieReader({ headers: new Headers({
    cookie: '__Secure-next-auth.session-token=s',
  })}), 's');
});

test('verifyRequest — valid cookie, no override', async () => {
  const req = { headers: { cookie: `__Secure-next-auth.session-token=${await mint(JIN)}` } };
  const { effective } = await verifyRequest(req, { secret: SECRET, capability: 'opil' });
  assert.equal(effective.customerCode, 'LNGCO');
  assert.equal(effective.siteName, 'LNG-DEMO');
});

test('verifyRequest — customer override not in JWT → 403', async () => {
  const req = { headers: {
    cookie: `__Secure-next-auth.session-token=${await mint(JIN)}`,
    'x-wyella-customer-id': 'GEOCO',
  }};
  await assert.rejects(() => verifyRequest(req, { secret: SECRET, capability: 'opil' }),
    e => e.code === 'customer_not_accessible' && e.httpStatus === 403);
});

test('verifyRequest — sysadmin wildcard accepts override', async () => {
  const req = { headers: {
    cookie: `__Secure-next-auth.session-token=${await mint(SYS)}`,
    'x-wyella-customer-id': 'LNGCO',
  }};
  const { effective } = await verifyRequest(req, { secret: SECRET, capability: null });
  assert.equal(effective.customerCode, 'LNGCO');
});

test('verifyRequest — site override not in JWT → 403', async () => {
  const req = { headers: {
    cookie: `__Secure-next-auth.session-token=${await mint(JIN)}`,
    'x-wyella-site-id': 'GEO-FACTORY',
  }};
  await assert.rejects(() => verifyRequest(req, { secret: SECRET, capability: 'opil' }),
    e => e.code === 'site_not_accessible');
});

test('verifyRequest — capability denied → 403', async () => {
  const tok = await mint({ ...JIN, capabilities: ['hsse'] });
  const req = { headers: { cookie: `__Secure-next-auth.session-token=${tok}` } };
  await assert.rejects(() => verifyRequest(req, { secret: SECRET, capability: 'equipment-care' }),
    e => e.code === 'capability_denied' && e.httpStatus === 403);
});

test('verifyRequest — sysadmin bypasses capability check', async () => {
  const req = { headers: { cookie: `__Secure-next-auth.session-token=${await mint(SYS)}` } };
  const { payload } = await verifyRequest(req, { secret: SECRET, capability: 'equipment-care' });
  assert.equal(payload.isSystemAdmin, true);
});

test('verifyRequest — tile-universal (capability: null)', async () => {
  const req = { headers: { cookie: `__Secure-next-auth.session-token=${await mint(JIN)}` } };
  const { payload } = await verifyRequest(req, { secret: SECRET, capability: null });
  assert.equal(payload.userId, JIN.userId);
});

test('verifyRequest — no cookie → 401', async () => {
  await assert.rejects(() => verifyRequest({ headers: {} }, { secret: SECRET, capability: 'opil' }),
    e => e.code === 'no_token' && e.httpStatus === 401);
});
