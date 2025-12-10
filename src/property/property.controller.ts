import {
  Body,
  Controller,
  Delete,
  Get,
  HttpException,
  HttpStatus,
  Param,
  Post,
  Put,
  Query,
  UploadedFiles,
  UseInterceptors,
  UseGuards,
} from '@nestjs/common';
import { PropertyService } from './property.service';
import {
  CreatePropertyDto,
  DeletePropertyImageDto,
  UpdatePropertyDto,
} from './dto/create-property.dto';
import { FileFieldsInterceptor } from '@nestjs/platform-express';
import { UpdateViewCountInterceptor } from 'src/interceptors/property.interceptors';
import { SubstractListigPackageOfBroker } from 'src/interceptors/property-quota.intercepors';
import { PropertyFilterType } from 'src/utils/filter.enum';
import { PropertyTypes } from 'src/utils/property.enum';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Roles } from 'src/guards/role.decorator';
import { Role } from 'src/utils/role.enum';

const imageVideoFileRegex = /\.(jpg|jpeg|png|webp)$/i;
const videoFileRegex = /\.(mp4|mov|avi)$/i;
@Controller('property')
export class PropertyController {
  constructor(private propertyService: PropertyService) {}

  @Post('/admin/create')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(
    FileFieldsInterceptor([
      { name: 'images[]', maxCount: 10 },
      { name: 'videoTour', maxCount: 1 },
    ]),
  )
  createPropertyByAdmin(
    @UploadedFiles()
    files: {
      images?: Express.Multer.File[];
      videoTour?: Express.Multer.File[];
    },
    @Body() createPropertyDto: CreatePropertyDto,
  ) {
    const { images, videoTour } = files;

    if (images) {
      for (const image of images) {
        // Check if the file is an image (jpg, jpeg, png, or webp)
        if (!image.originalname?.match(imageVideoFileRegex)) {
          throw new HttpException(
            'Invalid image file type.',
            HttpStatus.BAD_REQUEST,
          );
        }
      }
    }

    if (videoTour) {
      // Check if the file is a video (mp4, mov, or avi)
      if (!videoTour[0].originalname?.match(videoFileRegex)) {
        throw new HttpException(
          'Invalid Video file type.',
          HttpStatus.BAD_REQUEST,
        );
      }
    }
    return this.propertyService.createPropertyByAdmin(
      createPropertyDto,
      files['images[]'],
      videoTour && videoTour[0],
    );
  }

  //update property by admin
  @Put('/admin/update/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(
    FileFieldsInterceptor([
      { name: 'images[]', maxCount: 10 },
      { name: 'videoTour', maxCount: 1 },
    ]),
  )
  updatePropertyByAdmin(
    @UploadedFiles()
    files: {
      images?: Express.Multer.File[];
      videoTour?: Express.Multer.File[];
    },
    @Param('id') id: string,
    @Body() createPropertyDto: UpdatePropertyDto,
  ) {
    const { images, videoTour } = files;

    if (images) {
      for (const image of images) {
        // Check if the file is an image (jpg, jpeg, png, or webp)
        if (!image.originalname?.match(imageVideoFileRegex)) {
          throw new HttpException(
            'Invalid image file type.',
            HttpStatus.BAD_REQUEST,
          );
        }
      }
    }

    if (videoTour) {
      // Check if the file is a video (mp4, mov, or avi)
      if (!videoTour[0].originalname?.match(videoFileRegex)) {
        throw new HttpException(
          'Invalid Video file type.',
          HttpStatus.BAD_REQUEST,
        );
      }
    }
    return this.propertyService.updatePropertyByAdmin(
      id,
      createPropertyDto,
      files['images[]'],
      videoTour && videoTour[0],
    );
  }

  @Put('/broker/update/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker)
  @UseInterceptors(
    FileFieldsInterceptor([
      { name: 'images[]', maxCount: 10 },
      { name: 'videoTour', maxCount: 1 },
    ]),
  )
  updatePropertyByBroker(
    @UploadedFiles()
    files: {
      images?: Express.Multer.File[];
      videoTour?: Express.Multer.File[];
    },
    @Param('id') id: string,
    @Body() createPropertyDto: UpdatePropertyDto,
  ) {
    const { images, videoTour } = files;

    if (images) {
      for (const image of images) {
        // Check if the file is an image (jpg, jpeg, png, or webp)
        if (!image.originalname?.match(imageVideoFileRegex)) {
          throw new HttpException(
            'Invalid image file type.',
            HttpStatus.BAD_REQUEST,
          );
        }
      }
    }

    if (videoTour) {
      // Check if the file is a video (mp4, mov, or avi)
      if (!videoTour[0].originalname?.match(videoFileRegex)) {
        throw new HttpException(
          'Invalid Video file type.',
          HttpStatus.BAD_REQUEST,
        );
      }
    }
    return this.propertyService.updatePropertyByBroker(
      id,
      createPropertyDto,
      files['images[]'],
      videoTour && videoTour[0],
    );
  }

  //create property by broker
  @Post('/broker/create')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker)
  @UseInterceptors(
    SubstractListigPackageOfBroker,
    FileFieldsInterceptor([
      { name: 'images[]', maxCount: 10 },
      { name: 'videoTour', maxCount: 1 },
    ]),
  )
  createPropertyByBroker(
    @UploadedFiles()
    files: {
      images?: Express.Multer.File[];
      videoTour?: Express.Multer.File[];
    },
    @Body() createPropertyDto: CreatePropertyDto,
  ) {
    const { images, videoTour } = files;

    if (images) {
      for (const image of images) {
        // Check if the file is an image (jpg, jpeg, png, or webp)
        if (!image.originalname?.match(imageVideoFileRegex)) {
          throw new HttpException(
            'Invalid image file type.',
            HttpStatus.BAD_REQUEST,
          );
        }
      }
    }

    if (videoTour) {
      // Check if the file is a video (mp4, mov, or avi)
      if (!videoTour[0].originalname?.match(videoFileRegex)) {
        throw new HttpException(
          'Invalid Video file type.',
          HttpStatus.BAD_REQUEST,
        );
      }
    }
    return this.propertyService.createPropertyByBroker(
      createPropertyDto,
      files['images[]'],
      videoTour && videoTour[0],
    );
  }

  @Get('in-house')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getProperty(@Query('page') page = 1, @Query('perPage') perPage = 2) {
    return this.propertyService.getAllInHouseProperty(page, perPage);
  }
  // delete property bgy admin agent or broker
  @Delete('/find/delete/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker, Role.Admin)
  async deleteProperty(@Param('id') id: string) {
    await this.propertyService.deleteProperty(id);
  }

  //delete property image
  @Delete('/find-image/delete')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker, Role.Admin)
  async deletePropertyImage(@Body() data: DeletePropertyImageDto) {
    await this.propertyService.deletePropertyImage(data.id, data.imageId);
  }

  //property detail
  @Get('/find/detail/:id')
  async propertyDetail(@Param('id') id: string) {
    return await this.propertyService.propertyDetail(id);
  }

  //make property featured or not
  //change status make it sold out or rented out
  @Put('/admin/make-featured-or-not/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker, Role.Admin)
  async makePropertyFeaturedOrNotByAdmin(@Param('id') id: string) {
    return await this.propertyService.makePropertyFeaturedOrNotByAdmin(id);
  }
  //change status make it sold out or rented out
  @Put('/make-rent-or-sold/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker, Role.Admin)
  async makePropertyRentedOrSoldOut(@Param('id') id: string) {
    return await this.propertyService.makePropertyRentedOrSoldOut(id);
  }

  // make rented property back to normal
  @Put('/make-rented-back/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker, Role.Admin)
  async makeRentedPropertyBack(@Param('id') id: string) {
    return await this.propertyService.makeRentedPropertyBack(id);
  }
  // get all in house rented properties
  @Get('/in-house/rented')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllInHouseRentedProperty(
    @Query('page') page = 1,
    @Query('perPage') perPage = 2,
  ) {
    return await this.propertyService.getAllInHouseRentedProperty(
      page,
      perPage,
    );
  }

  //get all brokers property by admin or its agents
  @Get('/brokers/all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker, Role.Admin, Role.Agent)
  async getAllBrokersProperty(
    @Query('page') page = 1,
    @Query('perPage') perPage = 2,
  ) {
    return await this.propertyService.getAllBrokersProperty(page, perPage);
  }

  //get all featured properties getAllFeaturedPropertiesForAdmin
  @Get('/featured/admin/all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllFeaturedPropertiesForAdmin(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Query('type') type: PropertyFilterType,
  ) {
    return await this.propertyService.getAllFeaturedPropertiesForAdmin(
      page,
      perPage,
      type,
    );
  }

  //get all sold properties for admin getAllSoldPropertiesForAdmin
  @Get('/sold/admin/all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllSoldPropertiesForAdmin(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Query('type') type: PropertyFilterType,
  ) {
    return await this.propertyService.getAllSoldPropertiesForAdmin(
      page,
      perPage,
      type,
    );
  }
  //get all rented properties getAllRentedPropertiesForAdmin
  @Get('/rented/admin/all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllRentedPropertiesForAdmin(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Query('type') type: PropertyFilterType,
  ) {
    return await this.propertyService.getAllRentedPropertiesForAdmin(
      page,
      perPage,
      type,
    );
  }
  //* ----- action taken by admin -------------*
  @Put('verify/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async approveProperty(@Param('id') id: string) {
    return this.propertyService.verifyBrokersProperty(id);
  }
  //*-----------------------starting from this line the apis are for the user application section-------------------*
  @Get('featured/user/home-page')
  async getFeaturedPropertiesForUser() {
    return this.propertyService.getFeaturedPropertiesForUser();
  }

  // all featured properties
  @Get('featured/user/all')
  async getAllFeaturedPropertiesForUser(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
  ) {
    return this.propertyService.getAllFeaturedPropertiesForUser(page, perPage);
  }

  //get prperty by property type
  @Get('property-type/user/:id')
  async getPropertiesByPropertyType(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Param('id') id: string,
  ) {
    return this.propertyService.getPropertiesByPropertyType(page, perPage, id);
  }
  //get property detail for user
  @UseInterceptors(UpdateViewCountInterceptor)
  @Get('detail/user/:id')
  async getPropertyDetailForUser(@Param('id') id: string) {
    return this.propertyService.getPropertyDetailForUser(id);
  }
  //get recent listings for home page goes here
  @Get('latest/user/home-page')
  async getLatestListingPropertiesForHomePage() {
    return this.propertyService.getLatestListingPropertiesForHomePage();
  }

  //paginated latest properties getAllLatestListingProperties
  @Get('latest/user/all')
  async getAllLatestListingProperties(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
  ) {
    return this.propertyService.getAllLatestListingProperties(page, perPage);
  }
  //get property by owner
  @Get('owner/user/:id')
  async getPropertiesByOwner(
    @Param('id') id: string, //id owner id
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
  ) {
    return this.propertyService.getPropertiesByOwner(page, perPage, id);
  }
  // get property by broker
  @Get('broker/user/:id')
  async getPropertiesByBroker(
    @Param('id') id: string, //broker id
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
  ) {
    return this.propertyService.getPropertiesByBroker(page, perPage, id);
  }
  //get property by agent
  @Get('agent/user/:id')
  async getPropertiesByAgent(
    @Param('id') id: string, //broker id
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
  ) {
    return this.propertyService.getPropertiesByAgent(page, perPage, id);
  }

  //get filtered property
  @Get('filter/user')
  async getFilteredProperties(
    @Query('propertyType') propertyType: PropertyTypes,
    @Query('propertyHomeType') propertyHomeType: string,
    @Query('owner') owner: string,
    @Query('maxPrice') maxPrice: number,
    @Query('minPrice') minPrice: number,
    @Query('bathroom') bathroom: number,
    @Query('bedroom') bedroom: number,
    @Query('area') area: number,
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
  ) {
    return this.propertyService.getFilteredProperties({
      propertyType,
      propertyHomeType,
      owner,
      maxPrice,
      minPrice,
      bathroom,
      bedroom,
      area,
      page,
      perPage,
    });
  }

  //*-----------------------starting from this line the apis are for the brokers or agents section-------------------*
  // get property analytics
  @Get('broker/analytics/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Agent, Role.Broker)
  async getPropertyAnalyticForBroker(@Param('id') id: string) {
    return this.propertyService.getPropertyAnalyticForBroker(id);
  }

  @Get('broker/my-property/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Agent, Role.Broker)
  async getAllMyProperty(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Param('id') id: string,
  ) {
    return this.propertyService.getAllMyProperty(page, perPage, id);
  }

  //get all featured property for broker
  @Get('broker/featured/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Agent, Role.Broker)
  async getAllMyFeaturedPropertyForBroker(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Param('id') id: string,
  ) {
    return this.propertyService.getAllMyFeaturedPropertyForBroker(
      page,
      perPage,
      id,
    );
  }

  // get all in broker(mt) rented properties
  @Get('/broker/rented/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Agent, Role.Broker)
  async getAllMyRentedProperty(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Param('id') id: string,
  ) {
    return await this.propertyService.getAllMyRentedProperty(page, perPage, id);
  }

  // get all in broker(mt) sold properties
  @Get('/broker/sold/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Agent, Role.Broker)
  async getAllMySoldProperty(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Param('id') id: string,
  ) {
    return await this.propertyService.getAllMySoldProperty(page, perPage, id);
  }

  // get all in broker(mt) properties that are not in featured properties
  @Get('/broker/for-feature/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Agent, Role.Broker)
  async getAllPropertiesNotInFeaturedProperties(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Param('id') id: string,
  ) {
    return await this.propertyService.getAllPropertiesNotInFeaturedProperties(
      page,
      perPage,
      id,
    );
  }
}
