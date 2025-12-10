import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { GlobalSetting } from './schema/setting.schema';
import { Model } from 'mongoose';
import { GlobalSettingDto } from './dto/set-global-setting.dto';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';

@Injectable()
export class GlobalSettingsService {
  constructor(
    @InjectModel(GlobalSetting.name)
    private globalSettingSchema: Model<GlobalSetting>,
    private readonly cloudinaryService: CloudinaryService,
  ) {}

  //get setting
  async getGlobalSettings(): Promise<GlobalSetting> {
    return this.globalSettingSchema.findOne().exec();
  }
  //set Global Setting
  async setGlobalSetting(
    settings: GlobalSettingDto,
    logo: Express.Multer.File,
  ): Promise<GlobalSetting> {
    if (logo) {
      const imageUrl = await this.cloudinaryService.uploadFile(logo);
      return this.globalSettingSchema
        .findOneAndUpdate(
          {},
          { $set: { ...settings, appLogo: imageUrl.secure_url } },
          {
            new: true,
            upsert: true,
          },
        )
        .exec();
    }
    return this.globalSettingSchema
      .findOneAndUpdate({}, settings, {
        new: true,
        upsert: true,
      })
      .exec();
  }

  //get setting
  async getGlobalSettingsForBroker(): Promise<GlobalSetting> {
    return this.globalSettingSchema.findOne().exec();
  }

  //this is used by other module
  async getGlobalSetting(): Promise<GlobalSetting> {
    return this.globalSettingSchema.findOne().exec();
  }
}
