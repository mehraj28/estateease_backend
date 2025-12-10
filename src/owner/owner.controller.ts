import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Param,
  ParseFilePipeBuilder,
  Post,
  Put,
  Query,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { OwnerService } from './owner.service';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { CreateOwnerDto, UpdateOwnerDto } from './dto/create-owner.dto';
import { RoleGuard } from 'src/guards/role.guard';
import { Role } from 'src/utils/role.enum';
import { Roles } from 'src/guards/role.decorator';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';

@Controller('owner')
export class OwnerController {
  constructor(
    private ownerService: OwnerService,
    private readonly cloudinaryService: CloudinaryService,
  ) {}

  @Post('create')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(FileInterceptor('logo'))
  async createOwner(
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
    logo: Express.Multer.File,
    @Body() createOwnerDto: CreateOwnerDto,
  ) {
    return await this.ownerService.createOwner(createOwnerDto, logo);
  }

  @Put(':id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(FileInterceptor('logo'))
  async updateOwner(
    @Param('id')
    id: string,
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
          fileIsRequired: false,
        }),
    )
    logo: Express.Multer.File,
    @Body()
    updateOwnerDto: UpdateOwnerDto,
  ) {
    return await this.ownerService.updateOwner(id, updateOwnerDto, logo);
  }

  @Get('admin/all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getOwnerForAdmin(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
  ) {
    return await this.ownerService.getAllOwnerForAdmin(page, perPage);
  }

  @Get('all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  async getAllOwners() {
    return await this.ownerService.getAllOwners();
  }

  //*-----------------------starting from this line the apis are for the user application section-------------------*
  @Get('user/home-page')
  async getAllOwnersForUser() {
    return await this.ownerService.getAllOwnersForUser();
  }
}
