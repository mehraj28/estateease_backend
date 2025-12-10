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
    private readonly mailService: MailService,
    private readonly globalSettingService: GlobalSettingsService,
  ) {}

  // ✅ Create OTP for signup verification
  async createOtpForVerification(email: string) {
    const generatedCode = generateOTP();
    const hashedOtp = await hashedOtpOrPassword(generatedCode.toString());

    const otp = await this.otpModel.create({
      email,
      code: hashedOtp,
    });

    // ✅ SAFE SETTINGS ACCESS
    const appSetting = await this.globalSettingService.getGlobalSetting();
    const appLogo = appSetting?.appLogo ?? '';
    const appName = appSetting?.appName ?? 'EstateEase';

    await this.mailService.sendVerificationCodeToEmail(
      email,
      generatedCode,
      appLogo,
      appName,
    );

    return otp;
  }

  // ✅ Create OTP for forgot password
  async createOtpForForgotPassword(email: string) {
    const generatedCode = generateOTP();
    const hashedOtp = await hashedOtpOrPassword(generatedCode.toString());

    const otp = await this.otpModel.create({
      email,
      code: hashedOtp,
      isForForgotPassword: true,
    });

    // ✅ SAFE SETTINGS ACCESS
    const appSetting = await this.globalSettingService.getGlobalSetting();
    const appLogo = appSetting?.appLogo ?? '';
    const appName = appSetting?.appName ?? 'EstateEase';

    await this.mailService.sendVerificationCodeForForgotPasswordToEmail(
      email,
      generatedCode,
      appLogo,
      appName,
    );

    return otp;
  }

  // ✅ Verify OTP for signup
  async verifyOtpCodeForVerification(email: string, code: string) {
    const isOtpExist = await this.otpModel
      .findOne({
        email,
        isUsed: false,
        isForForgotPassword: false,
      })
      .sort({ createdAt: -1 });

    if (!isOtpExist) {
      throw new HttpException('Invalid Gateway', HttpStatus.BAD_GATEWAY);
    }

    const isOtpCorrect = await bcrypt.compare(
      code.toString(),
      isOtpExist.code.toString(),
    );

    if (!isOtpCorrect) {
      throw new HttpException('Invalid code', HttpStatus.BAD_REQUEST);
    }

    await this.otpModel.findByIdAndUpdate(isOtpExist._id, {
      $set: { isUsed: true },
    });

    return true;
  }

  // ✅ Verify OTP for forgot password
  async verifyOtpCodeForForgotPassword(email: string, code: string) {
    const isOtpExist = await this.otpModel
      .findOne({
        email,
        isUsed: false,
        isForForgotPassword: true,
      })
      .sort({ createdAt: -1 });

    if (!isOtpExist) {
      throw new HttpException('Invalid Gateway', HttpStatus.BAD_GATEWAY);
    }

    const isOtpCorrect = await bcrypt.compare(
      code.toString(),
      isOtpExist.code.toString(),
    );

    if (!isOtpCorrect) {
      throw new HttpException('Invalid code', HttpStatus.BAD_REQUEST);
    }

    await this.otpModel.findByIdAndUpdate(isOtpExist._id, {
      $set: { isUsed: true },
    });

    return 'verified';
  }
}
