import { UserKycStatus } from '../../../generated/prisma';

export interface BaseUserOptions {
  firstName: string;
  username?: string;
  email?: string;
  password?: string;
  customMessage?: string | null;
}

export interface EmployeeCredentialsOptions extends BaseUserOptions {
  role: string;
  permissions?: string[];
  actionType?: 'created' | 'reset';
}

export interface BusinessUserCredentialsOptions extends BaseUserOptions {
  transactionPin: string;
  actionType?: 'created' | 'reset';
}

export interface RootUserCredentialsOptions extends BaseUserOptions {
  actionType?: 'created' | 'reset';
}

export interface PasswordResetOptions {
  firstName: string;
  resetUrl: string;
  expiryMinutes?: number;
  supportEmail?: string | null;
  customMessage?: string | null;
}

export interface EmailVerificationOptions {
  firstName: string;
  verifyUrl: string;
}

export interface EmailTemplateResult {
  subject: string;
  html: string;
  text: string;
}

export interface UserKycStatusOptions {
  firstName: string;
  kycId: string;
  status: UserKycStatus;
  reason?: string;
  supportEmail?: string;
}
