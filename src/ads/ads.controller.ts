import {
  Body,
  Query,
  Controller,
  Delete,
  Get,
  HttpStatus,
  Param,
  ParseFilePipeBuilder,
  Post,
  Put,
  UploadedFile,
  UseInterceptors,
  UseGuards,
} from '@nestjs/common';
import { AdsService } from './ads.service';
import { FileInterceptor } from '@nestjs/platform-express';
import { CreateAdsByAdminDto, CreateAdsDto } from './dto/create-ads.dt';
import { SendAdsNotificationAndEmailInterceptor } from 'src/interceptors/notification.interceptors';
import { AdsFilterType } from 'src/utils/filter.enum';
import { Roles } from 'src/guards/role.decorator';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Role } from 'src/utils/role.enum';

@Controller('ads')
export class AdsController {
  constructor(private adsService: AdsService) {}

  @Post('post-ad')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker)
  @UseInterceptors(
    FileInterceptor('image'),
    SendAdsNotificationAndEmailInterceptor,
  )
  async postAd(
    @UploadedFile(
      new ParseFilePipeBuilder()
        .addFileTypeValidator({
          fileType: /(jpg|jpeg|png|webp)$/,
        })
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
        }),
    )
    image: Express.Multer.File,
    @Body() createAdsDto: CreateAdsDto,
  ) {
    return await this.adsService.createAds(createAdsDto, image);
  }

  //create ads by admin
  @Post('admin/post-ad')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(FileInterceptor('image'))
  async createAdminAds(
    @UploadedFile(
      new ParseFilePipeBuilder()
        .addFileTypeValidator({
          fileType: /(jpg|jpeg|png|webp)$/,
        })
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
        }),
    )
    image: Express.Multer.File,
    @Body() createAdsDto: CreateAdsByAdminDto,
  ) {
    return await this.adsService.createAdminAds(createAdsDto, image);
  }
  //get all ads the end date is less than today
  @Get('user/get-all-ads')
  async getAllAdsForUser() {
    return await this.adsService.getAllAdsForUser();
  }
  //*******************Broker End Point **************** */
  //get all ads for broker
  @Get('broker/get-all-ads/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker)
  async getAllAdsForBroker(
    @Body('page') page: number,
    @Body('perPage') perPage: number,
    @Param('id') id: string,
  ) {
    return await this.adsService.getAllAdsForBroker(page, perPage, id);
  }

  //get ads details for broker
  @Get('broker/get-ads-details/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker, Role.Admin)
  async getAdsDetailsForBroker(@Param('id') id: string) {
    return await this.adsService.getAdsDetailsByBroker(id);
  }

  //************admin end point *****************************/
  //get all ads for admin
  @Get('admin/get-all-ads')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllAdsForAdmin(
    @Query('page') page: number,
    @Query('perPage') perPage: number,
    @Query('type') type: AdsFilterType,
  ) {
    return await this.adsService.getAllAdsForAdmin(page, perPage, type);
  }

  //get all ads of brokers  for admin getAllBrokerAdsForAdmin
  @Get('admin/get-all-broker-ads')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllBrokerAdsForAdmin(
    @Query('page') page: number,
    @Query('perPage') perPage: number,
    @Query('perPage') type: AdsFilterType,
  ) {
    return await this.adsService.getAllBrokerAdsForAdmin(page, perPage, type);
  }
  //approve ads
  @Put('admin/approve-ads/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(SendAdsNotificationAndEmailInterceptor)
  async approveAdsByAdmin(@Param('id') id: string) {
    return await this.adsService.approveAdsByAdmin(id);
  }

  //reject ads
  @Put('admin/reject-ads/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async rejectAdsByAdmin(@Param('id') id: string) {
    return await this.adsService.rejectAdsByAdmin(id);
  }

  //---------------common end point--------------//
  //delete ad
  @Delete('/find/delete/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin, Role.Broker)
  async deleteAd(@Param('id') id: string) {
    return await this.adsService.deletedAd(id);
  }
}
