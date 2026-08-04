import { Injectable, Logger } from '@nestjs/common';
import { Resend } from 'resend';

@Injectable()
export class EmailService {
  private readonly resend: Resend;
  private readonly logger = new Logger(EmailService.name);
  private readonly fromEmail = 'Backend Template <academy@audecosmetics.com>';

  constructor() {
    this.resend = new Resend(process.env.RESEND_API_KEY);
  }

  async sendWelcomeEmail(
    email: string,
    firstName: string,
    temporaryPassword: string,
  ): Promise<void> {
    const frontendUrl = process.env.FRONTEND_URL;

    try {
      await this.resend.emails.send({
        from: this.fromEmail,
        to: email,
        subject: 'Welcome to Backend Template - Your Account Details',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h1 style="color: #1a1a1a;">Welcome to Backend Template!</h1>
            <p>Hi ${firstName},</p>
            <p>Your account has been created by an administrator. Here are your login credentials:</p>
            <div style="background-color: #f5f5f5; padding: 16px; border-radius: 8px; margin: 16px 0;">
              <p style="margin: 4px 0;"><strong>Email:</strong> ${email}</p>
              <p style="margin: 4px 0;"><strong>Temporary Password:</strong> ${temporaryPassword}</p>
            </div>
            <p>Please login and change your password immediately.</p>
            <a href="${frontendUrl}/login" style="display: inline-block; background-color: #0066cc; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; margin-top: 8px;">Login Now</a>
            <p style="margin-top: 24px; color: #666;">Best regards,<br>Backend Template Team</p>
          </div>
        `,
      });
      this.logger.log(`Welcome email sent to ${email}`);
    } catch (error) {
      this.logger.error(`Failed to send welcome email to ${email}`, error);
      throw error;
    }
  }

  async sendEmailVerificationEmail(
    email: string,
    firstName: string,
    token: string,
  ): Promise<void> {
    const frontendUrl = process.env.FRONTEND_URL;
    const verifyUrl = `${frontendUrl}/auth/verify-email?token=${token}`;

    try {
      await this.resend.emails.send({
        from: this.fromEmail,
        to: email,
        subject: 'Backend Template - Confirm Your Email',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h1 style="color: #1a1a1a;">Confirm Your Email</h1>
            <p>Hi ${firstName},</p>
            <p>Thanks for signing up! Please confirm your email address to activate your account.</p>
            <a href="${verifyUrl}" style="display: inline-block; background-color: #0066cc; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; margin-top: 8px;">Confirm Email</a>
            <p style="margin-top: 16px; color: #666; font-size: 14px;">Or paste this link into your browser:</p>
            <p style="color: #666; font-size: 12px; word-break: break-all;">${verifyUrl}</p>
            <p style="color: #999; font-size: 12px;">This link expires in 24 hours.</p>
            <p style="margin-top: 24px; color: #666;">Best regards,<br>Backend Template Team</p>
          </div>
        `,
      });
      this.logger.log(`Email verification sent to ${email}`);
    } catch (error) {
      this.logger.error(`Failed to send email verification to ${email}`, error);
      throw error;
    }
  }

  async sendPasswordResetEmail(
    email: string,
    firstName: string,
    token: string,
  ): Promise<void> {
    const frontendUrl = process.env.FRONTEND_URL;
    const resetUrl = `${frontendUrl}/auth/reset-password?token=${token}`;
    const timestamp = new Date().toISOString();

    try {
      await this.resend.emails.send({
        from: this.fromEmail,
        to: email,
        subject: 'Backend Template - Password Reset Request',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h1 style="color: #1a1a1a;">Password Reset Request</h1>
            <p>Hi ${firstName},</p>
            <p>We received a request to reset your password. Click the button below to choose a new one.</p>
            <a href="${resetUrl}" style="display: inline-block; background-color: #0066cc; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; margin-top: 8px;">Reset Password</a>
            <p style="margin-top: 16px; color: #666; font-size: 14px;">Or paste this link into your browser:</p>
            <p style="color: #666; font-size: 12px; word-break: break-all;">${resetUrl}</p>
            <p style="color: #999; font-size: 12px;">This link expires in 1 hour and can only be used once.</p>
            <p style="margin-top: 16px; color: #cc0000; font-size: 14px;">If you didn't request this password reset, you can safely ignore this email — your password will not change.</p>
            <p style="color: #999; font-size: 12px;">This password reset was requested on ${timestamp}.</p>
            <p style="margin-top: 16px; color: #666;">Best regards,<br>Backend Template Team</p>
          </div>
        `,
      });
      this.logger.log(`Password reset email sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send password reset email to ${email}`,
        error,
      );
      throw error;
    }
  }

  async sendPasswordRecoveryEmail(
    email: string,
    firstName: string,
    temporaryPassword: string,
  ): Promise<void> {
    const frontendUrl = process.env.FRONTEND_URL;
    const timestamp = new Date().toISOString();

    try {
      await this.resend.emails.send({
        from: this.fromEmail,
        to: email,
        subject: 'Backend Template - Password Reset Request',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h1 style="color: #1a1a1a;">Password Reset Request</h1>
            <p>Hi ${firstName},</p>
            <p>We received a request to reset your password for your Backend Template account.</p>
            <div style="background-color: #f5f5f5; padding: 16px; border-radius: 8px; margin: 16px 0;">
              <p style="margin: 4px 0;"><strong>Your new temporary password:</strong> ${temporaryPassword}</p>
            </div>
            <p>Please login with this temporary password and change it immediately.</p>
            <a href="${frontendUrl}/login" style="display: inline-block; background-color: #0066cc; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; margin-top: 8px;">Login Now</a>
            <p style="margin-top: 24px; color: #cc0000; font-size: 14px;">If you didn't request this password reset, please contact support immediately.</p>
            <p style="color: #999; font-size: 12px;">This password reset was requested on ${timestamp}.</p>
            <p style="margin-top: 16px; color: #666;">Best regards,<br>Backend Template Team</p>
          </div>
        `,
      });
      this.logger.log(`Password recovery email sent to ${email}`);
    } catch (error) {
      this.logger.error(
        `Failed to send password recovery email to ${email}`,
        error,
      );
      throw error;
    }
  }
}
