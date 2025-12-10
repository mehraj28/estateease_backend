import {
  Body,
  Controller,
  Get,
  HttpStatus,
  ParseFilePipeBuilder,
  Post,
  UploadedFile,
  UseInterceptors,
  UseGuards,
} from '@nestjs/common';
import { GlobalSettingsService } from './global-settings.service';
import { GlobalSettingDto } from './dto/set-global-setting.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Roles } from 'src/guards/role.decorator';
import { Role } from 'src/utils/role.enum';

@Controller('global-settings')
export class GlobalSettingsController {
  constructor(private globalSettingsService: GlobalSettingsService) {}

  //set global setting
  @Post('set')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin, Role.Broker)
  @UseInterceptors(FileInterceptor('logo'))
  async setGlobalSettings(
    @UploadedFile(
      new ParseFilePipeBuilder()
        // .addFileTypeValidator({
        //   fileType: /(jpg|jpeg|png|webp)$/,
        // })
        // .addMaxSizeValidator({
        //   maxSize: 10000,
        // })
        // .addValidator(
        //   new MaxFileSize({
        //     maxSize: 10000,
        //   }),
        // )
        .build({
          errorHttpStatusCode: HttpStatus.UNPROCESSABLE_ENTITY,
          fileIsRequired: false,
        }),
    )
    logo: Express.Multer.File,
    @Body() data: GlobalSettingDto,
  ) {
    return await this.globalSettingsService.setGlobalSetting(data, logo);
  }

  //get global setting
  @Get('all')
  async getGlobalSettings() {
    return await this.globalSettingsService.getGlobalSettings();
  }

  @Get('broker')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin, Role.Broker)
  async getGlobalSettingsForBroker() {
    return await this.globalSettingsService.getGlobalSettingsForBroker();
  }
}
