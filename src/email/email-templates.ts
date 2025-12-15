import type {
  BusinessUserCredentialsOptions,
  EmailTemplateResult,
  EmailVerificationOptions,
  EmployeeCredentialsOptions,
  PasswordResetOptions,
  RootUserCredentialsOptions,
} from '../interface/auth.interface';

class EmailTemplates {
  static generateEmployeeCredentialsTemplate(
    options: EmployeeCredentialsOptions,
  ): EmailTemplateResult {
    const {
      firstName,
      username,
      email,
      password,
      role,
      permissions = [],
      actionType = 'created',
      customMessage,
    } = options;

    const formattedFirstName = this.formatName(firstName);

    const actionText =
      actionType === 'reset'
        ? 'Your Employee Account Credentials Have Been Reset'
        : 'Your Employee Account Has Been Created';

    const description =
      actionType === 'reset'
        ? 'Your employee account credentials have been reset. Here are your new login details:'
        : 'Your employee account has been successfully created. Here are your login details:';

    const dynamicMessage = customMessage || description;

    return {
      subject: `Employee Account ${actionType === 'reset' ? 'Credentials Reset' : 'Created'}`,

      html: `
      <!DOCTYPE html>
      <html>
      <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Employee Credentials</title>
          <style>
              ${this.getCommonStyles()}
              .role-info {
                background: #e8f5e8;
                border-left: 4px solid #28a745;
                padding: 15px;
                margin: 15px 0;
                border-radius: 4px;
              }
              .permissions-list {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 6px;
                margin: 15px 0;
              }
              .permission-item {
                display: inline-block;
                background: #4F46E5;
                color: white;
                padding: 4px 12px;
                margin: 4px;
                border-radius: 20px;
                font-size: 12px;
              }
          </style>
      </head>

      <body>
        <div class="container">
            <div class="header" style="background: linear-gradient(135deg, #1e40af, #3730a3);">
                <h1>${actionText}</h1>
                <p>${actionType === 'reset' ? 'Updated Credentials' : 'Welcome!'}</p>
            </div>

            <div class="content">
                <p class="greeting">Hello <strong>${formattedFirstName}</strong>,</p>

                <div class="instruction-box">
                    <h3>${actionText}</h3>
                    <p>${dynamicMessage}</p>
                </div>

                <div class="role-info">
                    <h4>Assigned Role</h4>
                    <p><strong>${role}</strong></p>
                </div>

                ${
                  permissions.length
                    ? `
                    <div class="permissions-list">
                        <h4>Assigned Permissions</h4>
                        ${permissions
                          .map(
                            (p) => `<span class="permission-item">${p}</span>`,
                          )
                          .join('')}
                    </div>
                    `
                    : ''
                }

                <div class="credentials-card">
                    <h3>Login Credentials</h3>
                    <div class="credential-item"><span>Username:</span> ${username}</div>
                    <div class="credential-item"><span>Email:</span> ${email}</div>
                    <div class="credential-item"><span>Password:</span> ${password}</div>
                </div>
            </div>

            <div class="footer">
                Employee System Access - Confidential
            </div>
        </div>
      </body>
      </html>
      `,

      text: this.generateEmployeeCredentialsPlainText(options),
    };
  }

  static generateBusinessUserCredentialsTemplate(
    options: BusinessUserCredentialsOptions,
  ): EmailTemplateResult {
    const {
      firstName,
      username,
      email,
      password,
      transactionPin,
      actionType = 'created',
      customMessage,
    } = options;

    const formattedFirstName = this.formatName(firstName);

    const actionText =
      actionType === 'reset'
        ? 'Your Business Account Credentials Have Been Reset'
        : 'Your Business Account Has Been Created';

    const description =
      actionType === 'reset'
        ? 'Your business account credentials have been reset.'
        : 'Your business account has been created.';

    return {
      subject: `Business Account ${actionType === 'reset' ? 'Credentials Reset' : 'Created'}`,

      html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8" />
        <style>${this.getCommonStyles()}</style>
      </head>

      <body>
        <div class="container">
            <div class="header" style="background: linear-gradient(135deg, #059669, #047857);">
                <h1>${actionText}</h1>
            </div>

            <div class="content">
                <p class="greeting">Hello <strong>${formattedFirstName}</strong>,</p>

                <div class="instruction-box">
                    <h3>${actionText}</h3>
                    <p>${customMessage || description}</p>
                </div>

                <div class="credentials-card">
                    <h3>Account Credentials</h3>
                    <div class="credential-item"><span>Username:</span> ${username}</div>
                    <div class="credential-item"><span>Email:</span> ${email}</div>
                    <div class="credential-item"><span>Password:</span> ${password}</div>
                    <div class="credential-item"><span>Transaction PIN:</span> ${transactionPin}</div>
                </div>
            </div>

            <div class="footer">Business Account Services</div>
        </div>
      </body>
      </html>
      `,

      text: this.generateBusinessUserCredentialsPlainText(options),
    };
  }

  static generateRootUserCredentialsTemplate(
    options: RootUserCredentialsOptions,
  ): EmailTemplateResult {
    const {
      firstName,
      username,
      email,
      password,
      actionType = 'created',
      customMessage,
    } = options;

    const formattedFirstName = this.formatName(firstName);

    const actionText =
      actionType === 'reset'
        ? 'Your Root Administrator Credentials Have Been Reset'
        : 'Your Root Administrator Account Has Been Created';

    return {
      subject: `Root Administrator Account ${actionType === 'reset' ? 'Credentials Reset' : 'Created'}`,

      html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8" />
        <style>${this.getCommonStyles()}</style>
      </head>

      <body>
        <div class="container">
            <div class="header" style="background: linear-gradient(135deg, #dc2626, #b91c1c);">
                <h1>${actionText}</h1>
            </div>

            <div class="content">
                <p class="greeting">Hello <strong>${formattedFirstName}</strong>,</p>

                <div class="instruction-box">
                    <h3>${actionText}</h3>
                    <p>${customMessage || 'Your root admin account details are below:'}</p>
                </div>

                <div class="credentials-card">
                    <h3>Root Credentials</h3>
                    <div class="credential-item"><span>Username:</span> ${username}</div>
                    <div class="credential-item"><span>Email:</span> ${email}</div>
                    <div class="credential-item"><span>Password:</span> ${password}</div>
                </div>

                <div class="security-notice">
                    <h4>⚠️ HIGH SECURITY ACCOUNT</h4>
                    <p>This account has full system access. Handle carefully.</p>
                </div>
            </div>

            <div class="footer">Root Admin Access - CONFIDENTIAL</div>
        </div>
      </body>
      </html>
      `,

      text: this.generateRootUserCredentialsPlainText(options),
    };
  }

  static generatePasswordResetTemplate(
    options: PasswordResetOptions,
  ): EmailTemplateResult {
    const {
      firstName,
      resetUrl,
      expiryMinutes = 2,
      supportEmail,
      customMessage,
    } = options;

    const formattedFirstName = this.formatName(firstName);

    return {
      subject: 'Password Reset Instructions',

      html: `
      <!DOCTYPE html>
      <html>
      <head><style>${this.getCommonStyles()}</style></head>

      <body>
        <div class="container">
            <div class="header" style="background: linear-gradient(135deg, #4F46E5, #7E69E5);">
                <h1>Password Reset</h1>
            </div>

            <div class="content">
                <p>Hello <strong>${formattedFirstName}</strong>,</p>

                <div class="instruction-box">
                    <h3>Reset Your Password</h3>
                    <p>
                      ${
                        customMessage ||
                        'Click the button below to create a new password.'
                      }
                    </p>
                </div>

                <p style="text-align:center;">
                  <a href="${resetUrl}" class="reset-button">Reset Password</a>
                </p>

                <div class="url-backup">
                  <p>If the button does not work, use this link:</p>
                  <a href="${resetUrl}">${resetUrl}</a>
                </div>

                <div class="expiry-warning">
                  <strong>This link expires in ${expiryMinutes} minutes.</strong>
                </div>

                ${
                  supportEmail
                    ? `<p>Need help? Contact: <a href="mailto:${supportEmail}">${supportEmail}</a></p>`
                    : ''
                }
            </div>

            <div class="footer">This is an automated email.</div>
        </div>
      </body>
      </html>
      `,

      text: this.generatePasswordResetPlainText(options),
    };
  }

  static generateEmailVerificationTemplate(
    options: EmailVerificationOptions,
  ): EmailTemplateResult {
    const { firstName, verifyUrl } = options;

    const formattedFirstName = this.formatName(firstName);

    return {
      subject: 'Verify Your Email Address',

      html: `
      <!DOCTYPE html>
      <html>
      <head><style>${this.getCommonStyles()}</style></head>

      <body>
        <div class="container">
            <div class="header" style="background: linear-gradient(135deg, #047857, #059669);">
                <h1>Email Verification</h1>
            </div>

            <div class="content">
                <p>Hello <strong>${formattedFirstName}</strong>,</p>

                <div class="instruction-box">
                    <h3>Verify Your Email</h3>
                    <p>Please verify your email to activate your account.</p>
                </div>

                <p style="text-align:center;">
                  <a href="${verifyUrl}" class="reset-button">Verify Email</a>
                </p>

                <div class="url-backup">
                    <p>Or use this link:</p>
                    <a href="${verifyUrl}">${verifyUrl}</a>
                </div>
            </div>

            <div class="footer">This is an automated email.</div>
        </div>
      </body>
      </html>
      `,

      text: this.generateEmailVerificationPlainText(options),
    };
  }

  // ==================== PLAIN TEXT =====================

  static generateEmployeeCredentialsPlainText(
    options: EmployeeCredentialsOptions,
  ): string {
    const {
      firstName,
      username,
      email,
      password,
      role,
      permissions = [],
      actionType,
    } = options;

    return `
EMPLOYEE ACCOUNT ${actionType === 'reset' ? 'CREDENTIALS RESET' : 'CREATED'}

Name: ${this.formatName(firstName)}
Role: ${role}
Permissions: ${permissions.length ? permissions.join(', ') : 'None'}

Login:
Username: ${username}
Email: ${email}
Password: ${password}
    `.trim();
  }

  static generateBusinessUserCredentialsPlainText(
    options: BusinessUserCredentialsOptions,
  ): string {
    const { firstName, username, email, password, transactionPin, actionType } =
      options;

    return `
BUSINESS ACCOUNT ${actionType === 'reset' ? 'CREDENTIALS RESET' : 'CREATED'}

Name: ${this.formatName(firstName)}

Login:
Username: ${username}
Email: ${email}
Password: ${password}
PIN: ${transactionPin}
    `.trim();
  }

  static generateRootUserCredentialsPlainText(
    options: RootUserCredentialsOptions,
  ): string {
    const { firstName, username, email, password, actionType } = options;

    return `
ROOT ADMIN ACCOUNT ${actionType === 'reset' ? 'CREDENTIALS RESET' : 'CREATED'}

Name: ${this.formatName(firstName)}

Credentials:
Username: ${username}
Email: ${email}
Password: ${password}
    `.trim();
  }

  static generatePasswordResetPlainText(options: PasswordResetOptions): string {
    const { firstName, resetUrl, expiryMinutes } = options;

    return `
PASSWORD RESET

Hello ${this.formatName(firstName)},

Reset your password using this link:
${resetUrl}

This link expires in ${expiryMinutes} minutes.
    `.trim();
  }

  static generateEmailVerificationPlainText(
    options: EmailVerificationOptions,
  ): string {
    const { firstName, verifyUrl } = options;

    return `
EMAIL VERIFICATION

Hello ${this.formatName(firstName)},

Verify your email using this link:
${verifyUrl}
    `.trim();
  }

  // ==================== UTILITIES ======================

  static getCommonStyles(): string {
    return `
      body { font-family: 'Segoe UI', Tahoma, Verdana; background: #f5f5f5; }
      .container { max-width: 600px; margin: auto; background: #fff; }
      .header { padding: 20px; color: #fff; text-align: center; }
      .content { padding: 25px; }
      .greeting { font-size: 18px; margin-bottom: 15px; }
      .instruction-box { background: #e8f4fd; padding: 15px; border-left: 4px solid #4F46E5; border-radius: 4px; }
      .credentials-card { background: #f8f9fa; padding: 15px; margin-top: 20px; border-radius: 6px; }
      .credential-item { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid #ddd; }
      .reset-button { background: #4F46E5; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block; }
      .url-backup { margin-top: 15px; background: #f8f9fa; padding: 10px; border-radius: 6px; word-break: break-all; }
      .expiry-warning { margin-top: 15px; padding: 10px; background: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px; }
      .footer { text-align: center; padding: 20px; font-size: 14px; color: #555; }
    `;
  }

  static formatName(name: string): string {
    return name
      ? name
          .toLowerCase()
          .split(' ')
          .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
          .join(' ')
      : name;
  }
}

export default EmailTemplates;
