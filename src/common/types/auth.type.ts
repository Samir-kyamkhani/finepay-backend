export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export type PrincipalType = 'ROOT' | 'USER' | 'EMPLOYEE';

export interface JwtPayload {
  sub: string; // principal id (root.id / user.id / employee.id)
  principalType: PrincipalType;
  roleId?: string | null; // for ROOT + USER
  departmentId?: string | null; // for EMPLOYEE
  isRoot?: boolean; // fast bypass flag
}

export interface AuthActor {
  id: string;
  principalType: PrincipalType;
  isRoot: boolean;
  roleId?: string | null;
  rootId?: string;
  parentId: string;
}

export interface CookieOptions {
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  domain?: string;
  path: string;
  maxAge: number;
}

export interface SecurityConfig {
  accessTokenExpiry: string;
  refreshTokenExpiry: string;
  jwtSecret: string;
  bcryptSaltRounds: number;
  cookieDomain?: string;
  allowedOrigins: string[];
}

export interface AuditMetadata {
  [key: string]: any;
}
