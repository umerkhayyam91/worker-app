import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class NotificationsService {
  constructor(private readonly mailerService: MailerService) {}

  async sendEmailOtp(email: string, otp: string) {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Password Reset OTP',
      html: `
        <h1>Password Reset Request</h1>
        <p>Your OTP for password reset is: <strong>${otp}</strong></p>
        <p>This OTP will expire in 15 minutes.</p>
      `,
    });
  }

  async sendSmsOtp(phoneNumber: string, otp: string) {
    // TODO: Implement SMS sending logic using a service like Twilio
    console.log(`Sending OTP ${otp} to ${phoneNumber}`);
  }
} 