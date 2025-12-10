import { Body, Controller, Post, Get, Query, Param } from '@nestjs/common';
import { RatingService } from './rating.service';
import { RatePropertyDto } from './dto/rate-property.dto';

@Controller('rating')
export class RatingController {
  constructor(private ratingService: RatingService) {}

  //rate property by user  facility
  @Post('')
  async rateProperty(@Body() ratePropertyDto: RatePropertyDto) {
    return this.ratingService.rateProperty(ratePropertyDto);
  }

  //get paginated property rates
  @Get('property/all/:id')
  async getPropertiesByOwner(
    @Param('id') id: string, //id owner id
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
  ) {
    return this.ratingService.getPaginatedPropertyRatings(page, perPage, id);
  }
}
