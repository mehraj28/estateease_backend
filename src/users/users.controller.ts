import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Param,
  ParseFilePipeBuilder,
  Put,
  Query,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { FileInterceptor } from '@nestjs/platform-express';

@Controller('users')
export class UsersController {
  constructor(private userServices: UsersService) {}
  //get profile
  @Get('profile/:id')
  async getMyProfile(@Param('id') id: string) {
    return await this.userServices.getMyProfile(id);
  }

  //update profile
  @UseInterceptors(FileInterceptor('image'))
  @Put('profile/update/:id')
  async updateProfile(
    @Param('id') id: string,
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
    image: Express.Multer.File,
    @Body() updateProfileDto: UpdateProfileDto,
  ) {
    return await this.userServices.updateMyProfile(updateProfileDto, image, id);
  }

  @Get('end-users')
  async getProperty(@Query('page') page = 1, @Query('perPage') perPage = 2) {
    return this.userServices.getAllEndUsers(page, perPage);
  }
}
