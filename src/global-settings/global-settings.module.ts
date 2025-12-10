import { Module } from '@nestjs/common';
import { GlobalSettingsService } from './global-settings.service';
import { GlobalSettingsController } from './global-settings.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { GlobalSetting, GlobalSettingSchema } from './schema/setting.schema';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: GlobalSetting.name, schema: GlobalSettingSchema },
    ]),
  ],
  providers: [GlobalSettingsService, CloudinaryService],
  controllers: [GlobalSettingsController],
  exports: [GlobalSettingsService],
})
export class GlobalSettingsModule {}
