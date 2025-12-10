import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Favorite } from './schema/favorite.schema';
import { Model } from 'mongoose';
import { UsersService } from 'src/users/users.service';
import { PropertyService } from 'src/property/property.service';

@Injectable()
export class FavoriteService {
  constructor(
    @InjectModel(Favorite.name) private favoriteModel: Model<Favorite>,
    private userService: UsersService,
    private propertyService: PropertyService,
  ) {}

  //   add to favorite
  async addToWishList(userId: string, data: any) {
    // first if user is exist or not
    const isUserExist = await this.userService.findUserById(userId);
    if (!isUserExist) {
      throw new HttpException('user not found', HttpStatus.NOT_FOUND);
    }
    // check if the property is exist or not
    const isPropertyExist = await this.propertyService.findPropertyById(
      data.property,
    );
    if (!isPropertyExist) {
      throw new HttpException('Property not found', HttpStatus.NOT_FOUND);
    }
    // first find user favorite products
    const userFavorites = await this.favoriteModel.findOne({ user: userId });
    if (userFavorites) {
      //then find if it is already exist or not
      const isPropertyAlreadyInFavorite = userFavorites?.properties.some(
        (item) => item == data.property,
      );
      if (isPropertyAlreadyInFavorite)
        throw new HttpException(
          'property is already in favorite',
          HttpStatus.CONFLICT,
        );
      //if not exist push it to the array
      const updatedUserFavorite = await this.favoriteModel.findOneAndUpdate(
        { user: userId },
        { $push: { properties: data.property } },
        { new: true },
      );
      return updatedUserFavorite;
    } else {
      //create the user favorite
      const createUserFavorite = new this.favoriteModel({
        _id: userId,
        user: userId,
        properties: data.property,
      });
      const saveUserFavorite = await createUserFavorite.save();
      return saveUserFavorite;
    }
  }

  //remove from favorite
  async removeFromWishList(userId: string, data: any) {
    // first if user is exist or not
    const isUserExist = await this.userService.findUserById(userId);
    if (!isUserExist) {
      throw new HttpException('user not found', HttpStatus.NOT_FOUND);
    }
    // check if the property is exist or not
    const isPropertyExist = await this.propertyService.findPropertyById(
      data.property,
    );
    if (!isPropertyExist) {
      throw new HttpException('Property not found', HttpStatus.NOT_FOUND);
    }
    // check if the user property is in user whish list
    const userFavorites = await this.favoriteModel.findOne({ user: userId });
    const isPropertyInFavorite = userFavorites.properties?.some(
      (item) => item == data.property,
    );
    if (!isPropertyInFavorite) {
      throw new HttpException(
        'Property is not in your wishlist',
        HttpStatus.NOT_FOUND,
      );
    }
    const updatedUserFavorite = await this.favoriteModel.findOneAndUpdate(
      { user: userId },
      { $pull: { properties: data.property } },
      { new: true },
    );
    return updatedUserFavorite;
  }

  //get my wishlists
  async getMyWishLists(userId: string) {
    const isUserExist = await this.userService.findUserById(userId);
    if (!isUserExist) {
      throw new HttpException('user not found', HttpStatus.NOT_FOUND);
    }
    const userFavorite = await this.favoriteModel
      .findOne({ user: userId })
      .populate('properties');

    return userFavorite ?? { properties: [] };
  }
}
