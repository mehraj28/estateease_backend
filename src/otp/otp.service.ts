import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Otp } from './schema/otp.schema';
import { Model } from 'mongoose';
import { MailService } from 'src/services/mail.service';
import * as bcrypt from 'bcryptjs';
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

  //create otp for verification
  async createOtpForVerification(email: string) {
    const generatedCode = generateOTP();
    const hashedOtp = await hashedOtpOrPassword(generatedCode.toString());
    const otp = await this.otpModel.create({ email, code: hashedOtp });
    const appSetting = await this.globalSettingService.getGlobalSetting();
    //send the code via email
    await this.mailService.sendVerificationCodeToEmail(
      email,
      generatedCode,
      appSetting.appLogo,
      appSetting.appName,
    );
    return otp;
  }

  //create otp for forgot password
  async createOtpForForgotPassword(email: string) {
    const generatedCode = generateOTP();
    const hashedOtp = await hashedOtpOrPassword(generatedCode.toString());
    const appSetting = await this.globalSettingService.getGlobalSetting();
    const otp = await this.otpModel.create({
      email,
      code: hashedOtp,
      isForForgotPassword: true,
    });
    await this.mailService.sendVerificationCodeForForgotPasswordToEmail(
      email,
      generatedCode,
      appSetting.appLogo,
      appSetting.appName,
    );
    return otp;
  }

  //validate otp code and update status
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
    await this.otpModel.findByIdAndUpdate(
      isOtpExist._id,
      { $set: { isUsed: true } },
      { new: true },
    );
    return true;
  }

  //verify otp code for forgot password Abdi-Nexus123H
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
    await this.otpModel.findByIdAndUpdate(
      isOtpExist._id,
      { $set: { isUsed: true } },
      { new: true },
    );
    return 'verified';
  }
}
