import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import * as nodeMailer from 'nodemailer';
import * as path from 'path';
import * as EmailTemplates from 'email-templates';
import * as ejs from 'ejs';
import { format, parseISO } from 'date-fns';
import { da } from 'date-fns/locale';
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

  async sendVerificationCodeToEmail(
    email: string,
    verificationCode: number,
    logo: string,
    appName: string,
  ) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'verification-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        appName,
        verificationCode,
        logo,
      });
      const data = await this.transporter.sendMail({
        from: process.env.EMAIL_SENDER,
        to: email,
        subject: 'Please confirm your email address',
        html: templateContent,
      });
      return data;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }

  //send forgot password verification code
  async sendVerificationCodeForForgotPasswordToEmail(
    email: string,
    verificationCode: number,
    logo: string,
    appName: string,
  ) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'forgot-password-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        appName,
        verificationCode,
        logo,
      });
      const data = await this.transporter.sendMail({
        from: process.env.EMAIL_SENDER,
        to: email,
        subject: `${appName} account password reset`,
        html: templateContent,
      });

      return data;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }

  //========================Admin Email ===============================//

  //send email when new broker request is made
  async sendBrokerRequestEmailToAdmins(data: {
    recipients: string[];
    companyLogo: string;
    companyName: string;
    companyAddress: string;
    companyPhone: string;
    companyEmail: string;
    dashboardUrl: string;
    appLogo: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'broker-request-admin-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        companyName: data.companyName,
        companyLogo: data.companyLogo,
        companyAddress: data.companyAddress,
        companyPhone: data.companyPhone,
        companyEmail: data.companyEmail,
        dashboardLink: data.dashboardUrl,
        appLogo: data.appLogo,
      });
      const emailPromises = data.recipients.map((recipient) =>
        this.transporter.sendMail({
          from: process.env.EMAIL_SENDER, // Replace with your email address
          to: recipient,
          subject: `You have new broker's request from ${data.companyName}`,
          html: templateContent,
        }),
      );

      // Wait for all emails to be sent
      return await Promise.all(emailPromises);
    } catch (error) {
      console.log('error', error);
      throw new HttpException(
        'Error in sending email',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
  //send notification to admin when ads request is made
  async sendAdRequestEmailToAdmins(data: {
    recipients: string[];
    adTitle: string;
    adImage: string;
    broker: string;
    startDate: string;
    appLogo: string;
    endDate: string;
    dashboardUrl: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'ads-admin-email.ejs',
      );

      const templateContent = await ejs.renderFile(templatePath, {
        title: data.adTitle,
        image: data.adImage,
        startDate: format(new Date(data.startDate), 'd-MM-yyyy'),
        endDate: format(new Date(data.endDate), 'd-MM-yyyy'),
        broker: data.broker,
        appLogo: data.appLogo,
        dashboardLink: data.dashboardUrl,
      });
      // Create an array of promises for sending emails
      const emailPromises = data.recipients.map((recipient) =>
        this.transporter.sendMail({
          from: process.env.EMAIL_SENDER, // Replace with your email address
          to: recipient,
          subject: `You have new Ads request from ${data.broker}`,
          html: templateContent,
        }),
      );

      // Wait for all emails to be sent
      return await Promise.all(emailPromises);
    } catch (error) {
      console.error('Error sending emails:', error);
      throw error;
    }
  }
  // send notification to admin when featured property request is made
  async sendPropertyAdRequestEmailToAdmins(data: {
    recipients: string[];
    name: string;
    image: string;
    broker: string;
    appLogo: string;
    dashboardUrl: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'feature-property-admin-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        name: data.name,
        image: data.image,
        appLogo: data.appLogo,
        broker: data.broker,
        dashboardLink: data.dashboardUrl,
      });
      // Create an array of promises for sending emails
      const emailPromises = data.recipients.map((recipient) =>
        this.transporter.sendMail({
          from: process.env.EMAIL_SENDER, // Replace with your email address
          to: recipient,
          subject: `You have new Property Ads request from ${data.broker}`,
          html: templateContent,
        }),
      );

      // Wait for all emails to be sent
      return await Promise.all(emailPromises);
    } catch (error) {
      console.error('Error sending emails:', error);
      throw error;
    }
  }

  // send package request email to admin
  async sendPackageRequestEmailToAdmins(data: {
    recipients: string[];
    packageName: string;
    brokerLogo: string;
    maxListing: number;
    price: number;
    broker: string;
    appLogo: string;
    dashboardUrl: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'listing-package-admin-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        name: data.packageName,
        image: data.brokerLogo,
        maxListing: data.maxListing,
        price: data.price,
        broker: data.broker,
        appLogo: data.appLogo,
        dashboardLink: data.dashboardUrl,
      });
      // Create an array of promises for sending emails
      const emailPromises = data.recipients.map((recipient) =>
        this.transporter.sendMail({
          from: process.env.EMAIL_SENDER, // Replace with your email address
          to: recipient,
          subject: `You have new Listing Package Approval request from ${data.broker}`,
          html: templateContent,
        }),
      );

      // Wait for all emails to be sent
      return await Promise.all(emailPromises);
    } catch (error) {
      console.error('Error sending emails:', error);
      throw error;
    }
  }

  //send property report to admin
  async sendPropertyReportEmailToAdmins(data: {
    recipients: string[];
    userName: string;
    propertyName: string;
    reason: string;
    price: number;
    appLogo: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'property-report-admin-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        userName: data.userName,
        propertyName: data.propertyName,
        reason: data.reason,
        price: data.price,
        appLogo: data.appLogo,
      });
      // Create an array of promises for sending emails
      const emailPromises = data.recipients.map((recipient) =>
        this.transporter.sendMail({
          from: process.env.EMAIL_SENDER, // Replace with your email address
          to: recipient,
          subject: `new Property report by ${data.userName} on ${data.propertyName} `,
          html: templateContent,
        }),
      );

      // Wait for all emails to be sent
      return await Promise.all(emailPromises);
    } catch (error) {
      console.error('Error sending emails:', error);
      throw error;
    }
  }
  async sendEmailToAdmins(data: {
    recipients: string[];
    subject: string;
    text: string;
    html: string;
  }) {
    try {
      // Create an array of promises for sending emails
      const emailPromises = data.recipients.map((recipient) =>
        this.transporter.sendMail({
          from: process.env.EMAIL_SENDER, // Replace with your email address
          to: recipient,
          subject: data.subject,
          text: data.text,
          html: data.html,
        }),
      );

      // Wait for all emails to be sent
      return await Promise.all(emailPromises);
    } catch (error) {
      console.error('Error sending emails:', error);
      throw error;
    }
  }

  //=========================Broker or user Email ==============================//
  // send broker reject notification to broker
  async sendRequestRejectEmailToBroker(data: {
    recipient: string;
    companyLogo: string;
    companyName: string;
    companyAddress: string;
    companyPhone: string;
    companyEmail: string;
    reason: string;
    appLogo: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'broker-request-reject-broker-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        companyName: data.companyName,
        companyLogo: data.companyLogo,
        companyAddress: data.companyAddress,
        companyPhone: data.companyPhone,
        companyEmail: data.companyEmail,
        appLogo: data.appLogo,
        reason: data.reason,
      });
      const res = await this.transporter.sendMail({
        from: process.env.EMAIL_SENDER, // Replace with your email address
        to: data.recipient,
        subject: `Your Company ${data.companyName} request has been rejected `,
        html: templateContent,
      });
      return res;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
  //send email to broker when broker request is approved
  async sendRequestApprovalEmailToBroker(data: {
    recipient: string;
    companyLogo: string;
    companyName: string;
    companyAddress: string;
    companyPhone: string;
    companyEmail: string;
    dashboardUrl: string;
    appLogo: string;
    reason: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'broker-request-broker-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        companyName: data.companyName,
        companyLogo: data.companyLogo,
        companyAddress: data.companyAddress,
        companyPhone: data.companyPhone,
        companyEmail: data.companyEmail,
        dashboardLink: data.dashboardUrl,
        reason: data.reason,
        appLogo: data.appLogo,
      });
      const res = await this.transporter.sendMail({
        from: process.env.EMAIL_SENDER, // Replace with your email address
        to: data.recipient,
        subject: `Your Company ${data.companyName} request is Accepted! `,
        html: templateContent,
      });
      return res;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }

  //send ads approval email
  async sendAdsApprovalEmailToBroker(data: {
    recipient: string;
    adTitle: string;
    adImage: string;
    startDate: string;
    endDate: string;
    appLogo: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'ads-broker-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        title: data.adTitle,
        image: data.adImage,
        startDate: format(new Date(data.startDate), 'd-MM-yyyy'),
        endDate: format(new Date(data.endDate), 'd-MM-yyyy'),
        appLogo: data.appLogo,
      });
      const res = await this.transporter.sendMail({
        from: process.env.EMAIL_SENDER, // Replace with your email address
        to: data.recipient,
        subject: `Congragulation Your Ads ${
          data.adTitle
        } is Approved-Your Ads will be visible from ${format(
          new Date(data.startDate),
          'd-MM-yyyy',
        )} to ${format(new Date(data.endDate), 'd-MM-yyyy')}`,
        html: templateContent,
      });
      return res;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
  //send property ads approval email to broker
  async sendPropertyAdsApprovalEmailToBroker(data: {
    recipient: string;
    name: string;
    image: string;
    appLogo: string;
    dashboardUrl: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'feature-property-broker-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        name: data.name,
        image: data.image,
        appLogo: data.appLogo,
        dashboardLink: data.dashboardUrl,
      });
      const res = await this.transporter.sendMail({
        from: process.env.EMAIL_SENDER, // Replace with your email address
        to: data.recipient,
        subject: `Congratulation Your Property Ads request is Approved`,
        html: templateContent,
      });
      return res;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }

  //send listing package approval to broker
  async sendListingPackageApprovalEmailToBroker(data: {
    recipient: string;
    packageName: string;
    remining: string;
    maxListing: number;
    appLogo: string;
    dashboardUrl: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'listing-package-broker-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        name: data.packageName,
        remining: data.remining,
        maxListing: data.maxListing,
        appLogo: data.appLogo,
        dashboardLink: data.dashboardUrl,
      });
      const res = await this.transporter.sendMail({
        from: process.env.EMAIL_SENDER, // Replace with your email address
        to: data.recipient,
        subject: `Congratulation Your Listing Package ${data.packageName} gets Approved! You can now add ${data.maxListing} more listing`,
        html: templateContent,
      });
      return res;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
  // send report notification to broker
  async sendPropertyReportHiddenEmailToBroker(data: {
    recipient: string;
    message: string;
    propertyName: string;
    appLogo: string;
    dashboardUrl: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'property-report-broker-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        message: data.message,
        propertyName: data.propertyName,
        appLogo: data.appLogo,
        dashboardLink: data.dashboardUrl,
      });
      const res = await this.transporter.sendMail({
        from: process.env.EMAIL_SENDER, // Replace with your email address
        to: data.recipient,
        subject: `Your Property  ${data.propertyName} - temporary removed due to report from Multiple customers `,
        html: templateContent,
      });
      return res;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
  //send email to broker when property is visible
  async sendPropertyReportActivationEmailToBroker(data: {
    recipient: string;
    message: string;
    propertyName: string;
  }) {
    try {
      const templatePath = path.resolve(
        __dirname,
        '..',
        'templates',
        'property-report-broker-email.ejs',
      );
      const templateContent = await ejs.renderFile(templatePath, {
        message: 'congratulation your property is now visible to customers',
        propertyName: data.propertyName,
      });
      const res = await this.transporter.sendMail({
        from: process.env.EMAIL_SENDER, // Replace with your email address
        to: data.recipient,
        subject: `Your Property  ${data.propertyName} - which was  temporary removed due to report is now active `,
        html: templateContent,
      });
      return res;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
  async sendEmailToUser(data: {
    recipient: string;
    subject: string;
    text: string;
    html: string;
  }) {
    try {
      const res = await this.transporter.sendMail({
        from: process.env.EMAIL_SENDER, // Replace with your email address
        to: data.recipient,
        subject: data.subject,
        text: data.text,
        html: data.html,
      });
      return res;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
}
