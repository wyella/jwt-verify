// Next.js Edge middleware factory.
// Usage:
//   import { createJwtMiddleware } from '@wyella/jwt-verify/middleware';
//   export default createJwtMiddleware({
//     secret: process.env.NEXTAUTH_SECRET!, capability: 'opil',
//   });
//   export const config = {
//     matcher: ['/((?!api/health|_next/static|_next/image|favicon.ico).*)'],
//   };

import { NextResponse, type NextRequest } from 'next/server';
import { verifyRequest } from './index';
import { JwtVerifyError, type MiddlewareOptions } from './types';
import type { RevocationOptions } from './revocation';

const LOGIN = 'https://wyella.ca/login';
const FORBIDDEN = 'https://wyella.ca/platform';

/**
 * Resolve revocation options from MiddlewareOptions or env. Convention:
 *   WYELLA_REVOCATION_ENDPOINT — full URL of identity revocation endpoint
 *   WYELLA_REVOCATION_FAIL_OPEN — '1'|'true' to fail open (default fail-closed per OPE-254)
 *   WYELLA_REVOCATION_CACHE_MS — module-scope cache ttl, default 30000
 *
 * Returns undefined if no endpoint configured — middleware skips revocation
 * lookup and works as v0.1.x.
 */
function resolveRevocation(opts: MiddlewareOptions): RevocationOptions | undefined {
  if (opts.revocation) return opts.revocation;
  const endpoint = process.env.WYELLA_REVOCATION_ENDPOINT;
  if (!endpoint) return undefined;
  const failOpenRaw = process.env.WYELLA_REVOCATION_FAIL_OPEN ?? '';
  const cacheRaw = process.env.WYELLA_REVOCATION_CACHE_MS ?? '';
  return {
    endpoint,
    failOpen: failOpenRaw === '1' || failOpenRaw.toLowerCase() === 'true',
    cacheMs: cacheRaw ? Number(cacheRaw) : undefined,
  };
}

export function createJwtMiddleware(opts: MiddlewareOptions) {
  const loginUrl = opts.loginUrl ?? LOGIN;
  const forbiddenUrl = opts.forbiddenUrl ?? FORBIDDEN;
  const basePath = opts.basePath ?? '';
  const revocation = resolveRevocation(opts);

  return async function middleware(req: NextRequest): Promise<NextResponse> {
    try {
      const { payload, effective } = await verifyRequest(req, {
        secret: opts.secret, cookieName: opts.cookieName,
        maxAgeSeconds: opts.maxAgeSeconds, capability: opts.capability,
        revocation,
      });
      const h = new Headers(req.headers);
      h.set('x-wyella-user-id', payload.userId);
      h.set('x-wyella-customer-id', effective.customerCode);
      if (effective.siteName) h.set('x-wyella-site-id', effective.siteName);
      h.set('x-wyella-role', payload.role);
      return NextResponse.next({ request: { headers: h } });
    } catch (err) {
      if (err instanceof JwtVerifyError) {
        if (err.code === 'no_token' || err.code === 'invalid_token' || err.code === 'expired_token') {
          const target = new URL(loginUrl);
          const p = req.nextUrl.pathname + req.nextUrl.search;
          const cb = basePath && !p.startsWith(basePath) ? basePath + p : p;
          target.searchParams.set('callbackUrl', new URL(cb, req.nextUrl.origin).toString());
          return NextResponse.redirect(target, 302);
        }
        return NextResponse.redirect(forbiddenUrl, 302);
      }
      return NextResponse.redirect(loginUrl, 302);
    }
  };
}
