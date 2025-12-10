import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Put,
  Query,
  UseInterceptors,
  UseGuards,
} from '@nestjs/common';
import { FeaturedPropertyService } from './featured-property.service';
import { RequestFeaturedPropertyDto } from './dto/featured-property.dto';
import { SendFeaturePropertyNotificationAndEmailInterceptor } from 'src/interceptors/notification.interceptors';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Roles } from 'src/guards/role.decorator';
import { Role } from 'src/utils/role.enum';

@Controller('featured-property')
export class FeaturedPropertyController {
  constructor(private featuredPropertyService: FeaturedPropertyService) {}

  @Post('request')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin, Role.Broker)
  @UseInterceptors(SendFeaturePropertyNotificationAndEmailInterceptor)
  async requestFeaturedProperty(@Body() data: RequestFeaturedPropertyDto) {
    const featuredProperty =
      await this.featuredPropertyService.requestFeaturedProperty(data);
    return featuredProperty;
  }

  // get my own featured property for broker
  @Get('broker/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin, Role.Broker)
  async getAllFeaturedProperty(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Param('id') id: string,
  ) {
    return this.featuredPropertyService.getAllFeaturedProperty(
      page,
      perPage,
      id,
    );
  }

  //******************admin end point********** */
  @Get('admin/all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllFeaturedPropertyForAdmin(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
  ) {
    return this.featuredPropertyService.getAllFeaturedPropertyForAdmin(
      page,
      perPage,
    );
  }

  //approve request
  @Put('approve/admin/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(SendFeaturePropertyNotificationAndEmailInterceptor)
  async approveRequestForAdmin(
    @Param('id') id: string,
    @Body() data: { property: string },
  ) {
    return this.featuredPropertyService.approveBrokersFeaturedPropertyRequest(
      id,
      data.property,
    );
  }

  //=================common api for broker and admin===================//
  //get request detail
  @Get('detail/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin, Role.Broker)
  async getRequestDetail(@Param('id') id: string) {
    return this.featuredPropertyService.getRequestDetail(id);
  }
}
