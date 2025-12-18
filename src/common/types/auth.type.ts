export interface JwtPayload {
  sub: string;
  principalType: 'USER' | 'EMPLOYEE';
}

export interface SessionUser {
  userId: string;
  userType: 'ROOT' | 'USER' | 'EMPLOYEE';
  roleId?: string | null;
  departmentId?: string | null;
  businessId?: string | null;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
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
