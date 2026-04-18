// TokenPayload duplicates the JWT interface declared in
// wyella/identity/types/next-auth.d.ts — the authoritative OPE-168 v2
// shape. Duplicated, not imported, so this package has zero runtime
// dependency on wyella/identity.

export interface TokenPayload {
  userId: string;
  email?: string;
  isSystemAdmin: boolean;
  customerId: string;
  customerIds: string[];           // ['*'] = sysadmin wildcard
  siteId: string | null;
  siteIds: string[];               // no wildcard
  role: string;
  roleLabel: string;
  capabilities: string[];
  iat?: number;
  exp?: number;
  sub?: string;
  name?: string;
}

export interface VerifyOptions {
  secret: string;
  cookieName?: string;
  maxAgeSeconds?: number;          // default 43200 (12h) — DEC-915 / D-11
}

export interface MiddlewareOptions extends VerifyOptions {
  capability: string | null;        // null = tile-universal (LNG Twin)
  loginUrl?: string;                // default https://wyella.ca/login
  forbiddenUrl?: string;            // default https://wyella.ca/platform
  /**
   * Pass your Next.js app's `basePath` (e.g. `/opil`, `/lng-twin`).
   * Next.js strips `basePath` from `req.nextUrl.pathname` before
   * middleware runs, so without this option the `callbackUrl` on the
   * login redirect omits the prefix and the post-login bounce 404s.
   * Leave undefined for apps served at the root.
   *
   * Pair with `matcher: ['/', '/((?!...).*)']` so the basePath root
   * is also protected — the lookahead alone does not match `/`.
   */
  basePath?: string;
}

export interface EffectiveContext {
  userId: string;
  customerCode: string;
  siteName: string | null;
  role: string;
  isSystemAdmin: boolean;
}

export type VerifyErrorCode =
  | 'no_token' | 'invalid_token' | 'expired_token'
  | 'customer_not_accessible' | 'site_not_accessible' | 'capability_denied';

export class JwtVerifyError extends Error {
  constructor(
    readonly code: VerifyErrorCode,
    message: string,
    readonly httpStatus: number
  ) { super(message); this.name = 'JwtVerifyError'; }
}
