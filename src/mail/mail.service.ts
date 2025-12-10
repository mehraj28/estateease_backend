import { Injectable } from '@nestjs/common';
import * as nodeMailer from 'nodemailer';
import * as path from 'path';
import * as EmailTemplates from 'email-templates';
import * as ejs from 'ejs';
@Injectable()
export class MailService {
  private readonly transporter;
  private emailTemplates: EmailTemplates;
  constructor() {
    this.transporter = nodeMailer.createTransport({
      service: 'Mailjet', // You can also use 'SendGrid', 'Gmail', etc.
      auth: {
        user: process.env.MAILJET_API_KEY, // Replace with your Mailjet API key
        pass: process.env.MAILJET_API_SECRET, // Replace with your Mailjet API secret
      },
      // secure: true,
    });
  }

  // //send email
  async sendEmail() {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'verification-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        username: 'abebe',
        verificationCode: 256689,
      });
      console.log('templateContent', templateContent);
      const data = await this.transporter.sendMail({
        from: process.env.EMAIL_SENDER,
        to: 'tesfu9503@gmail.com',
        subject: 'Please confirm your email address with Logo',
        html: templateContent,
      });
      return data;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
}
