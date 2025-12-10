import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Put,
  UseGuards,
} from '@nestjs/common';
import { PackagesService } from './packages.service';
import { CreatePackageDto } from './dto/create-package.dto';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Roles } from 'src/guards/role.decorator';
import { Role } from 'src/utils/role.enum';

@Controller('packages')
export class PackagesController {
  constructor(private packageService: PackagesService) {}

  //create property by admin
  @Post('create')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async createNewPackage(@Body() createPackageDto: CreatePackageDto) {
    return this.packageService.createNewPackage(createPackageDto);
  }

  // update package
  @Put('update/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async updatePackage(
    @Param('id') id: string,
    @Body() createPackageDto: CreatePackageDto,
  ) {
    return this.packageService.updatePackage(createPackageDto, id);
  }

  //delete package
  @Put('remove/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async deletePackage(@Param('id') id: string) {
    return this.packageService.deletePackage(id);
  }

  //get all packages by admin or brokers
  @Get('find/all')
  async getAllPackages() {
    return this.packageService.getAllPackages();
  }

  @Get('find/:id')
  async getPackageById(@Param('id') id: string) {
    return this.packageService.getPackageById(id);
  }
}
