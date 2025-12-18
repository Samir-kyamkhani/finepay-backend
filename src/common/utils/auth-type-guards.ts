import { JwtPayload } from '../types/auth.type';

export function isJwtPayload(user: unknown): user is JwtPayload {
  return (
    typeof user === 'object' &&
    user !== null &&
    'sub' in user &&
    'principalType' in user
  );
}
