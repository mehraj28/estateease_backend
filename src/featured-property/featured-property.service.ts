import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { FeaturedProperty } from './schema/featured-property.schema';
import { Model } from 'mongoose';
import { RequestFeaturedPropertyDto } from './dto/featured-property.dto';
import { PropertyService } from 'src/property/property.service';
import { PaymentService } from 'src/payment/payment.service';
import { PaginationService } from 'src/services/pagination.service';
import { FeaturedPropertyStatus } from 'src/utils/status.enum';
import { FeaturePropertyAction } from 'src/utils/actions.enum';

@Injectable()
export class FeaturedPropertyService {
  constructor(
    @InjectModel(FeaturedProperty.name)
    private featuredPropertySchema: Model<FeaturedProperty>,
    private propertyService: PropertyService,
    private paymentService: PaymentService,
    private readonly paginationService: PaginationService,
  ) {}

  //update view count of the property or if the count of quota is over then remove the property from featured property
  async updateViewCount(propertyId: string) {
    const featuredProperty = await this.featuredPropertySchema.findOne({
      property: propertyId,
    });
    if (!featuredProperty) {
      return;
    }
    if (featuredProperty.viewCount === featuredProperty.numberOfViews) {
      //remove the property from featured property
      await this.propertyService.makePropertyUnFeatured(propertyId);
      await this.featuredPropertySchema.findByIdAndUpdate(
        featuredProperty._id,
        {
          isEnded: true,
          status: FeaturedPropertyStatus.STOPPED,
        },
        { new: true },
      );
    } else {
      featuredProperty.numberOfViews += 1;
      await featuredProperty.save();
    }
  }

  //request featured property
  async requestFeaturedProperty(data: RequestFeaturedPropertyDto) {
    const updatedFeaturedProperties = [];

    const existingFeaturedProperty = await this.featuredPropertySchema
      .findOne({
        property: data.property,
      })
      .populate('broker');

    if (existingFeaturedProperty) {
      // If the property exists in featured properties, update its view count and request payment
      existingFeaturedProperty.viewCount += data.viewCount;
      existingFeaturedProperty.isRequestUpdate = true;
      existingFeaturedProperty.status = FeaturedPropertyStatus.PENDING;
      // Request payment for the additional views
      const payment = await this.paymentService.makePaymentForFeaturedProperty(
        data,
      );
      // Update the payment info for the featured property
      existingFeaturedProperty.payment.push(payment);

      // Save the updated featured property
      const updatedProperty = await existingFeaturedProperty.save();

      // Populate the 'property' field and push it into the array
      const populatedProperty = await updatedProperty.populate('property');
      updatedFeaturedProperties.push(populatedProperty);
    } else {
      // If the property does not exist in featured properties, check if it exists in your system
      const isPropertyExist = await this.propertyService.findPropertyById(
        data.property,
      );

      if (isPropertyExist) {
        // Make the payment for the new featured property
        const payment =
          await this.paymentService.makePaymentForFeaturedProperty(data);

        // Create a new featured property for the single property
        const newFeaturedProperty = await this.featuredPropertySchema.create({
          property: data.property,
          payment: [payment._id],
          viewCount: data.viewCount,
          broker: data.broker,
          user: data.user,
        });
        // .populate('property');
        const newFeaturedPropertyPopulated = await this.featuredPropertySchema
          .findById(newFeaturedProperty._id)
          .populate('property')
          .populate('broker');

        updatedFeaturedProperties.push(newFeaturedPropertyPopulated);
      } else {
        throw new HttpException(
          'Property Does Not Exist',
          HttpStatus.BAD_REQUEST,
        );
      }
    }
    return {
      data: updatedFeaturedProperties,
      type: FeaturePropertyAction.CREATE,
    };
  }

  /*********************************** BROKER END POINT ****************************/
  async getAllFeaturedProperty(page: number, perPage: number, id: string) {
    const allProperties = await this.featuredPropertySchema
      .find({ broker: id })
      .populate('property');
    const totalProperties = allProperties.length;
    const paginatedData = this.paginationService.paginate(
      allProperties,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalProperties,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalProperties,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }

  //*****************admin end point ****************** */
  async getAllFeaturedPropertyForAdmin(page: number, perPage: number) {
    const allProperties = await this.featuredPropertySchema
      .find({})
      .populate('property');
    const totalProperties = allProperties.length;
    const paginatedData = this.paginationService.paginate(
      allProperties,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalProperties,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalProperties,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }

  //get request detail
  async getRequestDetail(id: string) {
    const request = await this.featuredPropertySchema
      .findById(id)
      .populate('property')
      .populate('broker')
      .populate('user')
      .populate('payment');
    if (!request) {
      throw new HttpException('Request Does Not Exist', HttpStatus.BAD_REQUEST);
    }
    return request;
  }

  //approve request
  async approveBrokersFeaturedPropertyRequest(id: string, property: string) {
    const request = await this.featuredPropertySchema.findById(id);
    if (!request) {
      throw new HttpException('Request Does Not Exist', HttpStatus.BAD_REQUEST);
    }
    const updateRequest = await this.featuredPropertySchema
      .findByIdAndUpdate(
        id,
        {
          status: FeaturedPropertyStatus.APPROVED,
        },
        { new: true },
      )
      .populate('property');
    await this.propertyService.makePropertyFeatured(property);

    //approve payment also
    for (const payment of request.payment) {
      await this.paymentService.approvePayment(payment.toString());
    }
    return { data: updateRequest, type: FeaturePropertyAction.APPROVE };
  }
}
