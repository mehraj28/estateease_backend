import { Body, Controller, Get, Param, Put } from '@nestjs/common';
import { FavoriteService } from './favorite.service';

@Controller('favorite')
export class FavoriteController {
  constructor(private favoriteService: FavoriteService) {}

  @Get('user/:id')
  async getMyWishLists(@Param('id') id: string) {
    return await this.favoriteService.getMyWishLists(id);
  }

  @Put('add/:id')
  async addToWishList(@Param('id') id: string, @Body() property: string) {
    return await this.favoriteService.addToWishList(id, property);
  }

  @Put('remove/:id')
  async removeFromWishList(@Param('id') id: string, @Body() property: string) {
    return await this.favoriteService.removeFromWishList(id, property);
  }
}
