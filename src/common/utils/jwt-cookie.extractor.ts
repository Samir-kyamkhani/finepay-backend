import type { Request } from 'express';

export function cookieJwtExtractor(req: Request): string | null {
  if (!req || !req.cookies) return null;

  const token: unknown = req.cookies.access_token;

  return typeof token === 'string' ? token : null;
}
