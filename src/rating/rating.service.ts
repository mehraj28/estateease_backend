import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { Rating } from './schema/rate.schema';
import mongoose, { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { RatePropertyDto } from './dto/rate-property.dto';
import { UsersService } from 'src/users/users.service';
import { PaginationService } from 'src/services/pagination.service';

@Injectable()
export class RatingService {
  constructor(
    @InjectModel(Rating.name) private ratingModel: Model<Rating>,
    private userService: UsersService,
    private paginationService: PaginationService,
  ) {}

  //rate property by user
  async rateProperty(ratePropertyDto: RatePropertyDto) {
    //check if the user exist or not
    const isUserExist = await this.userService.findUserById(
      ratePropertyDto.user,
    );
    if (!isUserExist) {
      throw new HttpException('user not found', HttpStatus.NOT_FOUND);
    }
    //check if the user rate the property or not if it's update the rate
    const isUserRate = await this.ratingModel.findOne({
      _id: ratePropertyDto.user,
      property: ratePropertyDto.property,
    });
    if (isUserRate) {
      // means update the rate
      const updateRating = await this.ratingModel.findByIdAndUpdate(
        ratePropertyDto.user,
        { ratePropertyDto },
        { new: true },
      );
      return updateRating;
    } else {
      // his first rating
      const userRating = await this.ratingModel.create(ratePropertyDto);
      return userRating;
    }
  }
  //get all rating of a property
  async getPropertyRates(propertyId: string) {
    const getAllRatings = await this.ratingModel
      .find({ property: propertyId })
      .populate('user')
      .limit(3)
      .sort({ createdAt: -1 });
    const totalRatings = await this.ratingModel
      .find()
      .countDocuments({ property: propertyId });
    const one = await this.ratingModel
      .find()
      .countDocuments({ property: propertyId, rate: 1 });
    const two = await this.ratingModel
      .find()
      .countDocuments({ property: propertyId, rate: 2 });
    const three = await this.ratingModel
      .find()
      .countDocuments({ property: propertyId, rate: 3 });
    const four = await this.ratingModel
      .find()
      .countDocuments({ property: propertyId, rate: 4 });
    const five = await this.ratingModel
      .find()
      .countDocuments({ property: propertyId, rate: 5 });
    const average = await this.ratingModel.aggregate([
      {
        $match: { property: new mongoose.Types.ObjectId(propertyId) },
      },
      {
        $group: {
          _id: null, // Group all documents into one group
          averageRating: { $avg: { $toDouble: '$rate' } }, // Calculate the average of the 'rate' field
        },
      },
    ]);

    return {
      getAllRatings,
      totalRatings,
      average: average[0]?.averageRating || 0,
      counts: { one, two, three, four, five },
    };
  }

  //get apginated property rates
  async getPaginatedPropertyRatings(page: number, perPage: number, id: string) {
    const allRatings = await this.ratingModel
      .find({ property: id })
      .populate('user');
    const totalRatings = allRatings.length;
    const paginatedData = this.paginationService.paginate(
      allRatings,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalRatings,
      perPage,
    );

    //counts

    const one = await this.ratingModel
      .find()
      .countDocuments({ property: id, rate: 1 });
    const two = await this.ratingModel
      .find()
      .countDocuments({ property: id, rate: 2 });
    const three = await this.ratingModel
      .find()
      .countDocuments({ property: id, rate: 3 });
    const four = await this.ratingModel
      .find()
      .countDocuments({ property: id, rate: 4 });
    const five = await this.ratingModel
      .find()
      .countDocuments({ property: id, rate: 5 });
    const average = await this.ratingModel.aggregate([
      {
        $match: { property: new mongoose.Types.ObjectId(id) },
      },
      {
        $group: {
          _id: null, // Group all documents into one group
          averageRating: { $avg: { $toDouble: '$rate' } }, // Calculate the average of the 'rate' field
        },
      },
    ]);
    return {
      average: average[0]?.averageRating || 0,
      counts: { one, two, three, four, five },
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalRatings,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
}
