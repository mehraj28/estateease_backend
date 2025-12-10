import {
  Controller,
  Get,
  Param,
  Query,
  Put,
  UseInterceptors,
  Body,
  UploadedFiles,
  UseGuards,
} from '@nestjs/common';
import { BrokersService } from './brokers.service';
import { FileFieldsInterceptor } from '@nestjs/platform-express';
import { UpdateBrokerDto } from './dto/create-broker.dto';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Roles } from 'src/guards/role.decorator';
import { Role } from 'src/utils/role.enum';

@Controller('brokers')
export class BrokersController {
  constructor(private brokersService: BrokersService) {}

  //get all brokers by admin
  @Get('/admin/all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllBrokers(@Query('page') page = 1, @Query('perPage') perPage = 2) {
    return await this.brokersService.getAllBrokers(page, perPage);
  }

  //get single broker
  @Get('/admin/single/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getBrokerById(@Param('id') id: string) {
    return await this.brokersService.getBrokerById(id);
  }
  //get company profile
  @Get('/detail/:id')
  async getBrokerDetail(@Param('id') id: string) {
    return await this.brokersService.getBrokerById(id);
  }

  //update company information
  @UseInterceptors(
    FileFieldsInterceptor([
      { name: 'logo', maxCount: 1 },
      { name: 'coverImage', maxCount: 1 },
    ]),
  )
  @Put('/update-info/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin, Role.Broker)
  async updateCompanyInfo(
    @Param('id') id: string,
    @UploadedFiles()
    files: {
      logo?: Express.Multer.File;
      coverImage?: Express.Multer.File;
    } = {},
    @Body() updateBrokerDto: UpdateBrokerDto,
  ) {
    const { logo, coverImage } = files;
    return await this.brokersService.updateCompanyInfo(
      id,
      updateBrokerDto,
      logo,
      coverImage,
    );
  }
}
