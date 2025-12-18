import { UserKycStatus } from '../../../generated/prisma/enums';
import {
  EmailTemplateResult,
  UserKycStatusOptions,
} from '../../common/types/email.type';

class KycEmailTemplates {
  // =============== SINGLE ENTRY POINT ===============
  static generate(
    status: UserKycStatus,
    options: UserKycStatusOptions,
  ): EmailTemplateResult {
    switch (status) {
      case UserKycStatus.VERIFIED:
        return this.verified(options);

      case UserKycStatus.REJECTED:
        return this.rejected(options);

      case UserKycStatus.SUSPENDED:
        return this.suspended(options);

      case UserKycStatus.PENDING:
      case UserKycStatus.UNDER_REVIEW:
      default:
        return this.submitted(options);
    }
  }

  // =============== TEMPLATES ===============

  private static submitted({
    firstName,
    kycId,
  }: UserKycStatusOptions): EmailTemplateResult {
    return {
      subject: 'Your KYC Is Under Review',
      html: this.wrap(`
        <h2>KYC Under Review</h2>
        <p>Hello <b>${this.name(firstName)}</b>,</p>
        <p>Your User KYC is under review.</p>
        <p><b>KYC ID:</b> ${kycId}</p>
      `),
      text: `Hello ${this.name(firstName)},
Your KYC is under review.
KYC ID: ${kycId}`,
    };
  }

  private static verified({
    firstName,
    kycId,
  }: UserKycStatusOptions): EmailTemplateResult {
    return {
      subject: '🎉 Your KYC Has Been Verified',
      html: this.wrap(`
        <h2 style="color:green;">KYC Verified</h2>
        <p>Hello <b>${this.name(firstName)}</b>,</p>
        <p>Your User KYC has been verified.</p>
        <p><b>KYC ID:</b> ${kycId}</p>
      `),
      text: `Hello ${this.name(firstName)},
Your KYC has been verified.
KYC ID: ${kycId}`,
    };
  }

  private static rejected({
    firstName,
    kycId,
    reason,
    supportEmail,
  }: UserKycStatusOptions): EmailTemplateResult {
    return {
      subject: '❌ Your KYC Has Been Rejected',
      html: this.wrap(`
        <h2 style="color:red;">KYC Rejected</h2>
        <p>Hello <b>${this.name(firstName)}</b>,</p>
        <p>Your User KYC has been rejected.</p>
        <p><b>KYC ID:</b> ${kycId}</p>
        ${reason ? `<p><b>Reason:</b> ${reason}</p>` : ''}
        ${supportEmail ? `<p>Support: ${supportEmail}</p>` : ''}
      `),
      text: `Hello ${this.name(firstName)},
Your KYC has been rejected.
KYC ID: ${kycId}
Reason: ${reason ?? 'Not specified'}`,
    };
  }

  private static suspended({
    firstName,
    kycId,
    supportEmail,
  }: UserKycStatusOptions): EmailTemplateResult {
    return {
      subject: '⚠️ Your KYC Has Been Suspended',
      html: this.wrap(`
        <h2 style="color:orange;">KYC Suspended</h2>
        <p>Hello <b>${this.name(firstName)}</b>,</p>
        <p>Your User KYC has been suspended.</p>
        <p><b>KYC ID:</b> ${kycId}</p>
        ${supportEmail ? `<p>Support: ${supportEmail}</p>` : ''}
      `),
      text: `Hello ${this.name(firstName)},
Your KYC has been suspended.
KYC ID: ${kycId}`,
    };
  }

  // =============== COMMON ===============

  private static wrap(content: string): string {
    return `
    <html>
      <body style="font-family:Arial;background:#f4f4f4;">
        <div style="max-width:600px;margin:auto;background:#fff;padding:20px;">
          ${content}
          <hr />
          <small>Fintech Compliance Team</small>
        </div>
      </body>
    </html>`;
  }

  private static name(name: string): string {
    return name
      .toLowerCase()
      .split(' ')
      .map((w) => w[0].toUpperCase() + w.slice(1))
      .join(' ');
  }
}

export default KycEmailTemplates;
