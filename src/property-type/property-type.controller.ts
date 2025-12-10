import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  Query,
  UseGuards,
} from '@nestjs/common';
import { PropertyTypeService } from './property-type.service';
import { CreatePropertyTypeDto } from './dto/create-propertyType.dto';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Role } from 'src/utils/role.enum';
import { Roles } from 'src/guards/role.decorator';

@Controller('property-type')
export class PropertyTypeController {
  constructor(private propertyTypeService: PropertyTypeService) {}

  //create PROPERTY TYPE
  @Post('create')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async createPropertyType(@Body() name: CreatePropertyTypeDto) {
    return await this.propertyTypeService.createPropertyType(name);
  }

  //bulk create property type createPropertyTypeBulk
  @Post('create/bulk')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async createPropertyTypeBulk(@Body() data: { data: string[] }) {
    return await this.propertyTypeService.createPropertyTypeBulk(data);
  }
  //update PropertyTypeDto
  @Put('update/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async updatePropertyType(
    @Body() name: CreatePropertyTypeDto,
    @Param('id') id: string,
  ) {
    return await this.propertyTypeService.updatePropertyType(name, id);
  }
  //delete PropertyTypeDto
  @Delete('delete/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async deletePropertyType(@Param('id') id: string) {
    return await this.propertyTypeService.deletePropertyType(id);
  }
  //get Property Type unpaginated
  @Get('')
  async getPropertyTypes() {
    return await this.propertyTypeService.getPropertyType();
  }

  //show single PropertyType
  @Get('find/:id')
  async getSinglePropertyType(@Param('id') id: string) {
    return await this.propertyTypeService.getSinglePropertyType(id);
  }
  //paginated for admin table
  @Get('all')
  async getAllPropertyTypes(
    @Query('page') page = 1,
    @Query('perPage') perPage = 2,
  ) {
    return this.propertyTypeService.getAllPropertyTypes(page, perPage);
  }
  //get property type for user
  @Get('user')
  async getPropertyTypeForUser() {
    return await this.propertyTypeService.getPropertyTypeForUser();
  }
}
