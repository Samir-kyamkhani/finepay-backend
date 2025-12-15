import { Injectable } from '@nestjs/common';
import nodemailer, { Transporter } from 'nodemailer';
import EmailTemplates from './email-templates';
import {
  EmployeeCredentialsOptions,
  BusinessUserCredentialsOptions,
  RootUserCredentialsOptions,
  PasswordResetOptions,
  EmailVerificationOptions,
} from '../interface/auth.interface';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class EmailService {
  private transporter: Transporter;
  private fromEmail: string;

  constructor(private config: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.config.get<string>('smtp.host'),
      port: this.config.get<number>('smtp.port'),
      secure: false,
      auth: {
        user: this.config.get<string>('smtp.user'),
        pass: this.config.get<string>('smtp.pass'),
      },
    });

    this.fromEmail = this.config.get<string>('smtp.fromEmail')!;
  }

  // GENERIC SEND EMAIL FUNCTION
  sendEmail(to: string, subject: string, text: string, html: string) {
    return this.transporter.sendMail({
      from: this.fromEmail,
      to,
      subject,
      text,
      html,
    });
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
