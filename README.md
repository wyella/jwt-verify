# @wyella/jwt-verify

[![npm](https://img.shields.io/npm/v/@wyella/jwt-verify.svg)](https://www.npmjs.com/package/@wyella/jwt-verify)

Edge-runtime JWE decode and Next.js middleware for the Wyella Digital Platform. The single integration boundary for the OPE-168 JWT v2 claims minted by `wyella-site` (NextAuth v4, `.wyella.ca` cookie) and consumed by the 19 Wyella apps.

## Install

```bash
npm install @wyella/jwt-verify
```

## Middleware

```ts
// middleware.ts
import { createJwtMiddleware } from '@wyella/jwt-verify/middleware';

export default createJwtMiddleware({
  secret: process.env.NEXTAUTH_SECRET!,
  capability: 'opil', // or null for tile-universal apps (LNG Twin)
});

export const config = {
  matcher: ['/((?!api/health|_next/static|_next/image|favicon.ico).*)'],
};
```

| Situation | Response |
|---|---|
| Missing / invalid / expired cookie | 302 → `https://wyella.ca/login?callbackUrl=<original>` |
| `X-Wyella-Customer-Id` header not in `token.customerIds` (or `['*']`) | 302 → `/platform` (403) |
| `X-Wyella-Site-Id` header not in `token.siteIds` | 302 → `/platform` (403) |
| Capability not in `token.capabilities` (unless sysadmin or `capability: null`) | 302 → `/platform` (403) |
| Valid + authorised | `NextResponse.next()` with `X-Wyella-User-Id` / `X-Wyella-Customer-Id` / `X-Wyella-Site-Id` / `X-Wyella-Role` request headers |

## Bearer-token / API-to-API

```ts
import { verifyJwt, type TokenPayload } from '@wyella/jwt-verify';
const payload: TokenPayload = await verifyJwt(bearerToken, {
  secret: process.env.NEXTAUTH_SECRET!,
});
```

## What it decodes

NextAuth v4 JWE — `alg='dir'`, `enc='A256GCM'`, 32-byte symmetric key HKDF-SHA256-derived from `NEXTAUTH_SECRET` (`salt=''`, `info='NextAuth.js Generated Encryption Key'`). Uses [`jose`](https://github.com/panva/jose) + Web Crypto, Edge-compatible. No `node:crypto`, no database access.

## TokenPayload

Duplicates the `JWT` interface declared in `wyella/identity/types/next-auth.d.ts`. When the platform advances to JWT shape v3, this package bumps a major version.

## Security

JWT security rests on `NEXTAUTH_SECRET` remaining secret in Vercel env; this package's source is public and the lock-shape publication is deliberate (OPE-170 Part 9). Report vulnerabilities privately at security@wyella.ca or via GitHub private advisories.

## License

Apache 2.0 — © 2026 Wyella Ltd.
