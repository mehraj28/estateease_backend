import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';

import { Otp } from './schema/otp.schema';
import { MailService } from 'src/services/mail.service';
import {
  generateOTP,
  hashedOtpOrPassword,
} from 'src/helpers/password.validator';
import { GlobalSettingsService } from 'src/global-settings/global-settings.service';

@Injectable()
export class OtpService {
  constructor(
    @InjectModel(Otp.name) private otpModel: Model<Otp>,
    private mailService: MailService,
    private readonly globalSettingService: GlobalSettingsService,
  ) {}

  // ✅ CREATE OTP FOR SIGNUP VERIFICATION
  async createOtpForVerification(email: string) {
    const generatedCode = generateOTP();
    const hashedOtp = await hashedOtpOrPassword(
      generatedCode.toString(),
    );

    const otp = await this.otpModel.create({
      email,
      code: hashedOtp,
    });

    const appSetting =
      await this.globalSettingService.getGlobalSetting();

    // ✅ EMAIL IS OPTIONAL — NEVER FAIL SIGNUP
    try {
      await this.mailService.sendVerificationCodeToEmail(
        email,
        generatedCode,
        appSetting?.appLogo || '',
        appSetting?.appName || 'Mirza Mehraj Baig Real Estate',
      );
    } catch (error) {
      console.error(
        'Email error (ignored during signup):',
        (error as any)?.message,
      );
    }

    return otp;
  }

  // ✅ CREATE OTP FOR FORGOT PASSWORD
  async createOtpForForgotPassword(email: string) {
    const generatedCode = generateOTP();
    const hashedOtp = await hashedOtpOrPassword(
      generatedCode.toString(),
    );

    const otp = await this.otpModel.create({
      email,
      code: hashedOtp,
      isForForgotPassword: true,
    });

    const appSetting =
      await this.globalSettingService.getGlobalSetting();

    try {
      await this.mailService.sendVerificationCodeForForgotPasswordToEmail(
        email,
        generatedCode,
        appSetting?.appLogo || '',
        appSetting?.appName || 'Mirza Mehraj Baig Real Estate',
      );
    } catch (error) {
      console.error(
        'Email error (ignored during forgot password):',
        (error as any)?.message,
      );
    }

    return otp;
  }

  // ✅ VERIFY OTP FOR SIGNUP
  async verifyOtpCodeForVerification(email: string, code: string) {
    const isOtpExist = await this.otpModel
      .findOne({
        email,
        isUsed: false,
        isForForgotPassword: false,
      })
      .sort({ createdAt: -1 });

    if (!isOtpExist) {
      throw new HttpException(
        'Invalid OTP',
        HttpStatus.BAD_REQUEST,
      );
    }

    const isOtpCorrect = await bcrypt.compare(
      code.toString(),
      isOtpExist.code.toString(),
    );

    if (!isOtpCorrect) {
      throw new HttpException(
        'Invalid code',
        HttpStatus.BAD_REQUEST,
      );
    }

    await this.otpModel.findByIdAndUpdate(isOtpExist._id, {
      $set: { isUsed: true },
    });

    return true;
  }

  // ✅ VERIFY OTP FOR FORGOT PASSWORD
  async verifyOtpCodeForForgotPassword(email: string, code: string) {
    const isOtpExist = await this.otpModel
      .findOne({
        email,
        isUsed: false,
        isForForgotPassword: true,
      })
      .sort({ createdAt: -1 });

    if (!isOtpExist) {
      throw new HttpException(
        'Invalid OTP',
        HttpStatus.BAD_REQUEST,
      );
    }

    const isOtpCorrect = await bcrypt.compare(
      code.toString(),
      isOtpExist.code.toString(),
    );

    if (!isOtpCorrect) {
      throw new HttpException(
        'Invalid code',
        HttpStatus.BAD_REQUEST,
      );
    }

    await this.otpModel.findByIdAndUpdate(isOtpExist._id, {
      $set: { isUsed: true },
    });

    return 'verified';
  }
}
