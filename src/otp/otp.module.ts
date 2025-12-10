import { Module } from '@nestjs/common';
import { OtpController } from './otp.controller';
import { OtpService } from './otp.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Otp, OtpSchema } from './schema/otp.schema';
import { MailService } from 'src/services/mail.service';
import { GlobalSettingsModule } from 'src/global-settings/global-settings.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Otp.name, schema: OtpSchema }]),
    GlobalSettingsModule,
  ],
  controllers: [OtpController],
  providers: [OtpService, MailService],
  exports: [OtpService],
})
export class OtpModule {}
