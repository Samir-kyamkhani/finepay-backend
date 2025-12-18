import {
  Injectable,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { CryptoService } from '../common/utils/crypto.utils';
import { SmtpConfigService } from '../smtp-config/smtp-config.service';
import {
  BusinessUserCredentialsOptions,
  EmailVerificationOptions,
<<<<<<< HEAD
  EmployeeCredentialsOptions,
  PasswordResetOptions,
  RootUserCredentialsOptions,
} from '../common/types/email.type';
import EmailTemplates from './templates/auth-email-templates';
=======
} from '../common/types/email.type';
import { ConfigService } from '@nestjs/config';
>>>>>>> 64a3bc47937e8ef376711e7b865e4127fd3d788a

@Injectable()
export class EmailService {
  constructor(
    private readonly smtpConfigService: SmtpConfigService,
    private readonly cryptoService: CryptoService,
  ) {}

  // ================= GET SUPPORT EMAIL =================
  async getSupportEmail(userId: string) {
    try {
      return await this.smtpConfigService.getSupportEmail(userId);
    } catch (err) {
      const error = err as Error;
      throw new InternalServerErrorException(
        'Failed to get support email in email file',
        error.message,
      );
    }
  }

  // ================= SEND MAIL USING USER'S SMTP =================
  async sendMail(
    senderUserId: string,
    to: string | string[],
    subject: string,
    html: string,
    text?: string,
  ): Promise<nodemailer.SentMessageInfo> {
    try {
      const smtp = await this.smtpConfigService.resolveSmtpConfig(senderUserId);

      const transporter = nodemailer.createTransport({
        host: smtp.host,
        port: smtp.port,
        secure: smtp.secure,
        auth: {
          user: smtp.username,
          pass: this.cryptoService.decrypt(smtp.passwordEnc),
        },
      });

      const mailOptions = {
        from: `"${smtp.fromName || 'Platform'}" <${smtp.fromEmail}>`,
        to: Array.isArray(to) ? to.join(', ') : to,
        subject,
        html,
        text: text || this.stripHtml(html),
      };

      return await transporter.sendMail(mailOptions);
    } catch (err) {
      const error = err as Error;
      if (error.message.includes('not found')) {
        throw new BadRequestException('No active SMTP configuration found');
      }
      throw new InternalServerErrorException('Failed to send email');
    }
  }

  // ================= PRIVATE HELPERS =================
  private stripHtml(html: string): string {
    return html.replace(/<[^>]*>/g, '');
  }

  // EMPLOYEE CREDENTIALS EMAIL
  sendEmployeeCredentialsEmail(options: EmployeeCredentialsOptions) {
    const template =
      EmailTemplates.generateEmployeeCredentialsTemplate(options);

    return this.sendEmail(
      options.email!,
      template.subject,
      template.text,
      template.html,
    );
  }

  // BUSINESS USER CREDENTIALS EMAIL
  sendBusinessUserCredentialsEmail(options: BusinessUserCredentialsOptions) {
    const template =
      EmailTemplates.generateBusinessUserCredentialsTemplate(options);

    return this.sendEmail(
      options.email!,
      template.subject,
      template.text,
      template.html,
    );
  }
  // ROOT USER CREDENTIALS EMAIL
  sendRootUserCredentialsEmail(options: RootUserCredentialsOptions) {
    const template =
      EmailTemplates.generateRootUserCredentialsTemplate(options);

    return this.sendEmail(
      options.email!,
      template.subject,
      template.text,
      template.html,
    );
  }

  // PASSWORD RESET EMAIL
  sendPasswordResetEmail(options: PasswordResetOptions) {
    const template = EmailTemplates.generatePasswordResetTemplate(options);

    return this.sendEmail(
      options.supportEmail || options.resetUrl, // fallback
      template.subject,
      template.text,
      template.html,
    );
  }
  // EMAIL VERIFICATION EMAIL
  sendEmailVerificationEmail(options: EmailVerificationOptions) {
    const template = EmailTemplates.generateEmailVerificationTemplate(options);

    return this.sendEmail(
      options.verifyUrl,
      template.subject,
      template.text,
      template.html,
    );
  }
}
