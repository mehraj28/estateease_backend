import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Put,
  Query,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { BrokerPackagesService } from './broker-packages.service';
import { CreateBrokerPackageDto } from './dto/create-broker-package.dto';
import { SendListingPackageNotificationAndEmailInterceptor } from 'src/interceptors/notification.interceptors';
import { Roles } from 'src/guards/role.decorator';
import { Role } from 'src/utils/role.enum';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';

@Controller('broker-packages')
export class BrokerPackagesController {
  constructor(private brokerPackageService: BrokerPackagesService) {}

  ///************broker end points********** */
  //buy package by broker
  @Post('buy-package')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker)
  @UseInterceptors(SendListingPackageNotificationAndEmailInterceptor)
  async buyListingPackage(@Body() data: CreateBrokerPackageDto) {
    return await this.brokerPackageService.buyListingPackage(data);
  }

  //get my active packages
  @Get('my-active-packages/:brokerId')
  async getMyActivePackages(@Param('brokerId') brokerId: string) {
    return await this.brokerPackageService.getMyActivePackages(brokerId);
  }

  //************admin end points********** */
  //get all listing requests
  @Get('all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllInHouseRentedProperty(
    @Query('page') page = 1,
    @Query('perPage') perPage = 2,
  ) {
    return await this.brokerPackageService.getAllListingRequests(page, perPage);
  }

  //approve listing requests
  @Put('approve/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(SendListingPackageNotificationAndEmailInterceptor)
  async approveListingRequest(@Param('id') id: string) {
    return await this.brokerPackageService.approveListingRequestPackage(id);
  }

  //get detail of request
  @Get('detail/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getSingleListingRequest(@Param('id') id: string) {
    return await this.brokerPackageService.getSingleListingRequest(id);
  }

  //==============brpoker end points================
  @Get('broker/all/:id')
  async getAllListingPackagesForBroker(
    @Param('id') id: string,
    @Query('page') page = 1,
    @Query('perPage') perPage = 2,
  ) {
    return await this.brokerPackageService.getAllListingPackagesForBroker(
      page,
      perPage,
      id,
    );
  }
}
