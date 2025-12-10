import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Property } from './schema/property.schema';
import mongoose, { Model } from 'mongoose';
import {
  CreatePropertyDto,
  FilterPropertyDto,
  UpdatePropertyDto,
} from './dto/create-property.dto';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { PaginationService } from 'src/services/pagination.service';
import { PropertyTypes } from 'src/utils/property.enum';
import { RatingService } from 'src/rating/rating.service';
import { FeaturedProperty } from 'src/featured-property/schema/featured-property.schema';
import { AdsService } from 'src/ads/ads.service';
import { PropertyFilterType } from 'src/utils/filter.enum';
import { BrokerPackagesService } from 'src/broker-packages/broker-packages.service';

@Injectable()
export class PropertyService {
  constructor(
    @InjectModel(Property.name) private PropertyModel: Model<Property>,
    @InjectModel(FeaturedProperty.name)
    private featuredPropertySchema: Model<FeaturedProperty>,
    private readonly cloudinaryService: CloudinaryService,
    private readonly paginationService: PaginationService,
    private readonly ratingService: RatingService,
    private readonly adsService: AdsService,
    private readonly brokerPackagesService: BrokerPackagesService,
  ) {}

  //update multitple properties agent
  async updateMultiplePropertiesAgent(
    prevAgent: string,
    agent: string,
  ): Promise<any> {
    return await this.PropertyModel.updateMany(
      { agent: prevAgent },
      { $set: { agent: agent } },
    );
  }

  //make property featured or remove from featured by admin no paymeent
  async makePropertyFeaturedOrNotByAdmin(id: string) {
    const property = await this.PropertyModel.findById(id);
    if (!property) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    if (property.isFeatured) {
      const makeItUnFeatured = await this.PropertyModel.findByIdAndUpdate(
        id,
        { $set: { isFeatured: false } },
        { new: true },
      );
      return makeItUnFeatured;
    }
    const makeItFeatured = await this.PropertyModel.findByIdAndUpdate(
      id,
      { $set: { isFeatured: true } },
      { new: true },
    );
    return makeItFeatured;
  }
  //hide the property from user by admin
  async hidePropertyFromUserByAdin(id: string) {
    return await this.PropertyModel.findByIdAndUpdate(
      id,
      { $set: { isHiddenByAdmin: true } },
      { new: true },
    );
  }
  //make the property activly visible
  async makeHiddenPropertyVisibleByAdmin(id: string) {
    return await this.PropertyModel.findByIdAndUpdate(
      id,
      { $set: { isHiddenByAdmin: false } },
      { new: true },
    );
  }
  //check if the property exist or not do not remove it is used by other module
  async findPropertyById(id: string): Promise<any> {
    return await this.PropertyModel.findById(id);
  }
  async populatePropertyInfo(model: any, path: string) {
    return await this.PropertyModel.populate(model, { path: path });
  }

  //make property featured used by other service
  async makePropertyFeatured(id: string) {
    const property = await this.PropertyModel.findById(id);
    if (!property) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    if (property.isFeatured) {
      throw new HttpException(
        'Property Already Featured',
        HttpStatus.NOT_FOUND,
      );
    }
    const makeItFeatured = await this.PropertyModel.findByIdAndUpdate(
      id,
      { $set: { isFeatured: true } },
      { new: true },
    );
    return makeItFeatured;
  }

  //make property un featured used by other service
  async makePropertyUnFeatured(id: string) {
    const property = await this.PropertyModel.findById(id);
    if (!property) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    if (!property.isFeatured) {
      throw new HttpException('Property is Not Featured', HttpStatus.NOT_FOUND);
    }
    const makeItUnFeatured = await this.PropertyModel.findByIdAndUpdate(
      id,
      { $set: { isFeatured: false } },
      { new: true },
    );
    return makeItUnFeatured;
  }
  //  get all in house property count
  async getAllInHousePropertyCount() {
    return await this.PropertyModel.countDocuments({
      broker: null,
      isInHouseProperty: true,
      isRented: false,
      isSoldOut: false,
      isDeleted: false,
    });
  }
  //get all brokers property count for admin only
  async getAllBrokersPropertyCount() {
    return await this.PropertyModel.countDocuments({
      isInHouseProperty: false,
      isDeleted: false,
    });
  }
  //get all featured property count for admin only
  async getAllFeaturedPropertyCount() {
    return await this.PropertyModel.countDocuments({
      isFeatured: true,
      isDeleted: false,
    });
  }
  //get all rented property count for admin only
  async getAllRentedPropertyCount() {
    return await this.PropertyModel.countDocuments({
      isRented: true,
      isDeleted: false,
    });
  }
  //get all sold property count for admin only
  async getAllSoldPropertyCount() {
    return await this.PropertyModel.countDocuments({
      isSoldOut: true,
      isDeleted: false,
    });
  }
  //for admin
  async createPropertyByAdmin(
    createPropertyDto: CreatePropertyDto,
    images: Express.Multer.File[],
    videoTour?: Express.Multer.File,
  ): Promise<any> {
    const uploadedImages = await this.cloudinaryService.uploadFiles(images);

    //check if video tour is available
    let uploadedVideoUrl: string | undefined;
    if (videoTour) {
      const uploadedVideo = await this.cloudinaryService.uploadFile(videoTour);
      uploadedVideoUrl = uploadedVideo.secure_url;
    }
    const newProperty = await this.PropertyModel.create({
      ...createPropertyDto,
      address: {
        ...createPropertyDto.address,
        loc: [
          Number(createPropertyDto.address.loc[0]),
          Number(createPropertyDto.address.loc[1]),
        ],
      },
      images: uploadedImages.map((response) => ({
        url: response.secure_url,
      })),
      VideoTour: uploadedVideoUrl,
      isInHouseProperty: true,
      broker: null,
      isApproved: true,
    });
    return newProperty;
  }
  //UPDAATE PROPERTY FOR ADMIN
  async updatePropertyByAdmin(
    id: string,
    createPropertyDto: UpdatePropertyDto,
    images?: Express.Multer.File[],
    videoTour?: Express.Multer.File,
  ): Promise<any> {
    const property = await this.PropertyModel.findById(id);
    if (!property) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    let uploadedImages: any;
    if (images) {
      const cloudnarymages = await this.cloudinaryService.uploadFiles(images);
      uploadedImages = cloudnarymages.map((response) => ({
        url: response.secure_url,
      }));
    }

    //check if video tour is available
    let uploadedVideoUrl: string | undefined;
    if (videoTour) {
      const uploadedVideo = await this.cloudinaryService.uploadFile(videoTour);
      uploadedVideoUrl = uploadedVideo.secure_url;
    }
    //update property
    if (uploadedImages) {
      const updateProperty = await this.PropertyModel.findByIdAndUpdate(
        id,
        {
          ...createPropertyDto,
          address: {
            ...createPropertyDto.address,
            loc: [
              Number(createPropertyDto.address.loc[0]),
              Number(createPropertyDto.address.loc[1]),
            ],
          },
          $push: { images: uploadedImages },
          VideoTour: uploadedVideoUrl,
        },
        { new: true },
      );

      return updateProperty;
    }
    const updateWithOutImage = await this.PropertyModel.findByIdAndUpdate(
      id,
      {
        ...createPropertyDto,
        address: {
          ...createPropertyDto.address,
          loc: [
            Number(createPropertyDto.address.loc[0]),
            Number(createPropertyDto.address.loc[1]),
          ],
        },
        VideoTour: uploadedVideoUrl,
      },
      { new: true },
    );

    return updateWithOutImage;
  }

  //update property for broker
  async updatePropertyByBroker(
    id: string,
    createPropertyDto: UpdatePropertyDto,
    images?: Express.Multer.File[],
    videoTour?: Express.Multer.File,
  ): Promise<any> {
    const property = await this.PropertyModel.findById(id);
    if (!property) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    let uploadedImages: any;
    if (images) {
      const cloudnarymages = await this.cloudinaryService.uploadFiles(images);
      uploadedImages = cloudnarymages.map((response) => ({
        url: response.secure_url,
      }));
    }

    //check if video tour is available
    let uploadedVideoUrl: string | undefined;
    if (videoTour) {
      const uploadedVideo = await this.cloudinaryService.uploadFile(videoTour);
      uploadedVideoUrl = uploadedVideo.secure_url;
    }
    //update property
    if (uploadedImages) {
      const updateProperty = await this.PropertyModel.findByIdAndUpdate(
        id,
        {
          ...createPropertyDto,
          address: {
            ...createPropertyDto.address,
            loc: [
              Number(createPropertyDto.address.loc[0]),
              Number(createPropertyDto.address.loc[1]),
            ],
          },
          $push: { images: uploadedImages },
          VideoTour: uploadedVideoUrl,
        },
        { new: true },
      );

      return updateProperty;
    }
    const updateWithOutImage = await this.PropertyModel.findByIdAndUpdate(
      id,
      {
        ...createPropertyDto,
        address: {
          ...createPropertyDto.address,
          loc: [
            Number(createPropertyDto.address.loc[0]),
            Number(createPropertyDto.address.loc[1]),
          ],
        },
        VideoTour: uploadedVideoUrl,
      },
      { new: true },
    );

    return updateWithOutImage;
  }

  //get all inHouse property for admin or agent who has permission
  async getAllInHouseProperty(page: number, perPage: number) {
    const allProperties = await this.PropertyModel.find({
      broker: null,
      isInHouseProperty: true,
      isRented: false,
      isSoldOut: false,
      isDeleted: false,
    })
      .populate('owner')
      .sort({ createdAt: -1 });
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
  //get all sold property for admin or agent who has permission
  async getAllSoldProperty(page: number, perPage: number) {
    const allProperties = await this.PropertyModel.find({
      // broker: null,
      isDeleted: false,
      isRented: false,
      isSoldOut: true,
    }).populate('owner');
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
  //get all in-house rented property for admin or agent who has permission
  async getAllInHouseRentedProperty(page: number, perPage: number) {
    const allProperties = await this.PropertyModel.find({
      broker: null,
      isInHouseProperty: true,
      isRented: true,
      isSoldOut: false,
      isDeleted: false,
    })
      .populate('owner')
      .sort({ updatedAt: -1 });
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

  //get all featured Property count for broker or admin
  async getAllFeaturedPropertyCountOfBroker(id: string) {
    return await this.PropertyModel.find({ isDeleted: false }).countDocuments({
      isFeatured: true,
      broker: id,
    });
  }

  //get all broker property count for broker or admin
  async getAllPropertyCountOfBroker(id: string) {
    return await this.PropertyModel.find().countDocuments({
      broker: id,
      isDeleted: false,
    });
  }
  //get all sold broker property count for broker or admin
  async getAllSoldPropertyCountOfBroker(id: string) {
    return await this.PropertyModel.find().countDocuments({
      broker: id,
      isSoldOut: true,
      isDeleted: false,
    });
  }
  //get all sold broker property count for broker or admin
  async getAllRentedPropertyCountOfBroker(id: string) {
    return await this.PropertyModel.find().countDocuments({
      broker: id,
      isRented: true,
      isDeleted: false,
    });
  }
  //get all brokers property for admin
  async getAllBrokersProperty(page: number, perPage: number) {
    const allProperties = await this.PropertyModel.find({
      isInHouseProperty: false,
      isDeleted: false,
    })
      .populate('owner')
      .populate('broker')
      .sort({ createdAt: -1 });
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

  //*-----------------------------------------------------------starting from this line the apis are for admin---------------------------*
  async getAllFeaturedPropertiesForAdmin(
    page: number,
    perPage: number,
    type: PropertyFilterType,
  ) {
    const { PropertyModel, paginationService } = this; // Destructure for readability

    // Create a common query object with shared conditions
    const commonQuery = {
      isSoldOut: false,
      isRented: false,
      isFeatured: true,
      isDeleted: false,
    };

    // Add type-specific conditions
    if (type === PropertyFilterType.InHouses) {
      commonQuery['isInHouseProperty'] = true;
      commonQuery['broker'] = null;
    } else if (type === PropertyFilterType.Brokers) {
      commonQuery['isInHouseProperty'] = false;
    }

    // Use Promise.all to parallelize multiple async calls
    const [allFeaturedProperties, totalProperties] = await Promise.all([
      PropertyModel.find(commonQuery).populate('owner').populate('broker'),
      PropertyModel.countDocuments(commonQuery),
    ]);

    const paginatedData = paginationService.paginate(
      allFeaturedProperties,
      page,
      perPage,
    );

    const totalPages = paginationService.calculateTotalPages(
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
  //get all sold properties for admin
  async getAllSoldPropertiesForAdmin(
    page: number,
    perPage: number,
    type: PropertyFilterType,
  ) {
    const { PropertyModel, paginationService } = this; // Destructure for readability

    // Create a common query object with shared conditions
    const commonQuery = {
      isSoldOut: true,
      isRented: false,
      isDeleted: false,
    };

    // Add type-specific conditions
    if (type === PropertyFilterType.InHouses) {
      commonQuery['isInHouseProperty'] = true;
      commonQuery['broker'] = null;
    } else if (type === PropertyFilterType.Brokers) {
      commonQuery['isInHouseProperty'] = false;
    }

    // Use Promise.all to parallelize multiple async calls
    const [allSoldProperties, totalProperties] = await Promise.all([
      PropertyModel.find(commonQuery).populate('owner').populate('broker'),
      PropertyModel.countDocuments(commonQuery),
    ]);

    const paginatedData = paginationService.paginate(
      allSoldProperties,
      page,
      perPage,
    );

    const totalPages = paginationService.calculateTotalPages(
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

  //get all rented properties
  async getAllRentedPropertiesForAdmin(
    page: number,
    perPage: number,
    type: PropertyFilterType,
  ) {
    const { PropertyModel, paginationService } = this; // Destructure for readability

    // Create a common query object with shared conditions
    const commonQuery = {
      isSoldOut: false,
      isRented: true,
      isDeleted: false,
    };

    // Add type-specific conditions
    if (type === PropertyFilterType.InHouses) {
      commonQuery['isInHouseProperty'] = true;
      commonQuery['broker'] = null;
    } else if (type === PropertyFilterType.Brokers) {
      commonQuery['isInHouseProperty'] = false;
    }

    // Use Promise.all to parallelize multiple async calls
    const [allRentedProperties, totalProperties] = await Promise.all([
      PropertyModel.find(commonQuery).populate('owner').populate('broker'),
      PropertyModel.countDocuments(commonQuery),
    ]);

    const paginatedData = paginationService.paginate(
      allRentedProperties,
      page,
      perPage,
    );

    const totalPages = paginationService.calculateTotalPages(
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
  //*-----------------------starting from this line the apis are for the user application section-------------------*
  //send ten of latest featured properties for the home page (currently not in use this api parked)
  async getFeaturedPropertiesForUser() {
    const latestFeaturedProperties = await this.PropertyModel.find({
      isSoldOut: false,
      isRented: false,
      isHiddenByAdmin: false,
      isHide: false,
      isDeleted: false,
    })
      .limit(10)
      .sort({ updatedAt: -1 });
    return latestFeaturedProperties;
  }
  //this is paginated all latest featured properties
  async getAllFeaturedPropertiesForUser(page: number, perPage: number) {
    const allFeaturedProperties = await this.PropertyModel.find({
      isSoldOut: false,
      isRented: false,
      isFeatured: true,
      isHiddenByAdmin: false,
      isHide: false,
      isDeleted: false,
    }).sort({ createdAt: -1 });
    const totalProperties = allFeaturedProperties.length;
    const paginatedData = this.paginationService.paginate(
      allFeaturedProperties,
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
  //get property detail for user
  async getPropertyDetailForUser(id: string) {
    let ads: any;
    const property = await this.PropertyModel.findById(id)
      .populate('owner')
      .populate('broker')
      .populate({
        path: 'agent',
        populate: {
          path: 'user',
        },
      })
      .populate('facilities.facility')
      .populate('amenities')
      .populate('propertyHomeType');
    if (!property) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    //send all property rating
    const propertyRating = await this.ratingService.getPropertyRates(id);
    //send related property for user

    const relatedProperties = await this.PropertyModel.find({
      $or: [
        { owner: (property.owner as any)?._id },
        { broker: (property.broker as any)?._id },
      ],
      propertyType: property.propertyType,
      _id: { $ne: id },
    });
    //send if there is ads
    if (property.isInHouseProperty) {
      ads = await this.adsService.getInHouseAds();
    } else {
      ads = await this.adsService.getBrokerAds((property.broker as any)._id);
    }
    return { property, propertyRating, ads, related: relatedProperties };
  }
  // update view count of property norrmal view not ads view count
  async updateViewCount(id: string) {
    await this.PropertyModel.findByIdAndUpdate(id, {
      $inc: { views: 1 },
    });
  }
  // get recently listed properties for user for home page limited to 10
  async getLatestListingPropertiesForHomePage() {
    return await this.PropertyModel.find({ isDeleted: false })
      .sort({ createdAt: -1 })
      .limit(10);
  }
  //get latest properties paginated
  async getAllLatestListingProperties(page: number, perPage: number) {
    const allOwnerProperties = await this.PropertyModel.find({
      isSoldOut: false,
      isRented: false,
      isHiddenByAdmin: false,
      isHide: false,
      isDeleted: false,
    }).sort({ createdAt: -1 });
    const totalProperties = allOwnerProperties.length;
    const paginatedData = this.paginationService.paginate(
      allOwnerProperties,
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
  //get property listing by owner(Real Estates)
  async getPropertiesByOwner(page: number, perPage: number, id: string) {
    const allOwnerProperties = await this.PropertyModel.find({
      owner: id,
      isSoldOut: false,
      isRented: false,
      isHiddenByAdmin: false,
      isHide: false,
      isDeleted: false,
    }).sort({ createdAt: -1 });
    const ads = await this.adsService.getAdsByOwner(id);
    const totalProperties = allOwnerProperties.length;
    const paginatedData = this.paginationService.paginate(
      allOwnerProperties,
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
      ads,
    };
  }
  //get properties by broker
  async getPropertiesByBroker(page: number, perPage: number, id: string) {
    const allOwnerProperties = await this.PropertyModel.find({
      broker: id,
      isSoldOut: false,
      isRented: false,
      isHiddenByAdmin: false,
      isHide: false,
      isDeleted: false,
    });
    const ads = await this.adsService.getBrokerAds(id);
    const totalProperties = allOwnerProperties.length;
    const paginatedData = this.paginationService.paginate(
      allOwnerProperties,
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
      ads,
    };
  }

  //get property by agent
  async getPropertiesByAgent(page: number, perPage: number, id: string) {
    const allAgentProperties = await this.PropertyModel.find({
      agent: id,
      isSoldOut: false,
      isRented: false,
      isHiddenByAdmin: false,
      isHide: false,
      isDeleted: false,
    });
    const ads = await this.adsService.getBrokerAds(id);
    const totalProperties = allAgentProperties.length;
    const paginatedData = this.paginationService.paginate(
      allAgentProperties,
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
      ads,
    };
  }

  //get property by property type
  async getPropertiesByPropertyType(page: number, perPage: number, id: string) {
    const allOwnerProperties = await this.PropertyModel.find({
      propertyHomeType: id,
      isSoldOut: false,
      isRented: false,
      isHiddenByAdmin: false,
      isHide: false,
      isDeleted: false,
    });
    const ads = await this.adsService.getBrokerAds(id);
    const totalProperties = allOwnerProperties.length;
    const paginatedData = this.paginationService.paginate(
      allOwnerProperties,
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
      ads,
    };
  }

  //filter property
  async getFilteredProperties(data: FilterPropertyDto) {
    const allProperties = await this.PropertyModel.find({
      $and: [
        data.propertyType ? { propertyType: data.propertyType } : {},
        data.owner ? { owner: data.owner } : {},
        {
          $or: [
            data.propertyHomeType
              ? { propertyHomeType: data.propertyHomeType }
              : {},
            data.maxPrice ? { amount: { $lte: data.maxPrice } } : {},
            data.minPrice ? { amount: { $gte: data.minPrice } } : {},
            data.bathroom ? { bathroom: { $gte: data.bathroom } } : {},
            data.bedroom ? { bedroom: { $gte: data.bedroom } } : {},
            data.area ? { area: { $gte: data.area } } : {},
          ],
        },
        { isSoldOut: false },
        { isRented: false },
        { isHiddenByAdmin: false },
        { isHide: false },
        { isDeleted: false },
      ],
    });
    const totalProperties = allProperties.length;
    const paginatedData = this.paginationService.paginate(
      allProperties,
      data.page,
      data.perPage ?? 10,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalProperties,
      data.perPage ?? 10,
    );
    return {
      pagination: {
        data: paginatedData,
        page: data.page,
        perPage: data.perPage,
        totalProperties,
        totalPages,
        hasNextPage: data.page < totalPages,
        hasPrevPage: data.page > 1,
      },
    };
  }
  // ------------actions taken by admin---------------//
  async verifyBrokersProperty(id: string) {
    const property = await this.PropertyModel.findById(id);
    if (!property) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    if (property.isApproved) {
      throw new HttpException(
        'Property Already Verified',
        HttpStatus.NOT_FOUND,
      );
    }
    const approveProperty = await this.PropertyModel.findByIdAndUpdate(
      id,
      { $set: { isApproved: true } },
      { new: true },
    );
    return approveProperty;
  }

  //*-----------------------starting from this line the apis are for brokers and their agents section-------------------*
  //create property for brokers
  async createPropertyByBroker(
    createPropertyDto: CreatePropertyDto,
    images: Express.Multer.File[],
    videoTour?: Express.Multer.File,
  ): Promise<any> {
    //check if the broker has package or not
    const brokerPackage: any =
      await this.brokerPackagesService.getMyActivePackages(
        createPropertyDto.broker,
      );
    // console.log(brokerPackage);

    if (!brokerPackage || brokerPackage?.freeListingQuotaRemaining < 1)
      throw new HttpException(
        'You are out of listing qouta please buy a package to list property',
        HttpStatus.NOT_FOUND,
      );
    if (brokerPackage?.package && brokerPackage?.package?.remining < 1)
      throw new HttpException(
        'You are out of listing qouta please buy a package to list property',
        HttpStatus.NOT_FOUND,
      );
    const uploadedImages = await this.cloudinaryService.uploadFiles(images);

    //check if video tour is available
    let uploadedVideoUrl: string | undefined;
    if (videoTour) {
      const uploadedVideo = await this.cloudinaryService.uploadFile(videoTour);
      uploadedVideoUrl = uploadedVideo.secure_url;
    }
    const newProperty = await this.PropertyModel.create({
      ...createPropertyDto,
      address: {
        ...createPropertyDto.address,
        loc: [
          Number(createPropertyDto.address.loc[0]),
          Number(createPropertyDto.address.loc[1]),
        ],
      },
      images: uploadedImages.map((response) => ({
        url: response.secure_url,
      })),
      VideoTour: uploadedVideoUrl,
      isInHouseProperty: false,
    });
    return newProperty;
  }
  async getAllMyProperty(page: number, perPage: number, id: string) {
    const allProperties = await this.PropertyModel.find({
      broker: id,
      isInHouseProperty: false,
      isRented: false,
      isSoldOut: false,
      isDeleted: false,
    }).populate('owner');
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
  //get all sold property for admin or agent who has permission
  async getAllMySoldProperty(page: number, perPage: number, id: string) {
    const allProperties = await this.PropertyModel.find({
      broker: id,
      isInHouseProperty: false,
      isRented: false,
      isSoldOut: true,
      isDeleted: false,
    }).populate('owner');
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

  //get all in-house rented property for admin or agent who has permission
  async getAllMyRentedProperty(page: number, perPage: number, id: string) {
    const allProperties = await this.PropertyModel.find({
      broker: id,
      isInHouseProperty: false,
      isRented: true,
      isSoldOut: false,
      isDeleted: false,
    }).populate('owner');
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

  //get all my featured property for broker
  async getAllMyFeaturedPropertyForBroker(
    page: number,
    perPage: number,
    id: string,
  ) {
    const allProperties = await this.PropertyModel.find({
      broker: id,
      isInHouseProperty: false,
      isRented: false,
      isSoldOut: false,
      isFeatured: true,
      isDeleted: false,
    }).populate('owner');
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
  //get all properties that are not in featured properties
  async getAllPropertiesNotInFeaturedProperties(
    page: number,
    perPage: number,
    id: string,
  ) {
    const allProperties = await this.PropertyModel.find({
      broker: id,
      isHide: false,
      isSoldOut: false,
      isRented: false,
      isDeleted: false,
    });
    const featuredProperties = await this.featuredPropertySchema.find();
    const featuredPropertiesIds = featuredProperties.map((property) =>
      property.property.toString(),
    );
    const allPropertiesNotInFeaturedProperties = allProperties.filter(
      (property) => !featuredPropertiesIds.includes(String(property.id)),
    );
    const totalProperties = allPropertiesNotInFeaturedProperties.length;
    const paginatedData = this.paginationService.paginate(
      allPropertiesNotInFeaturedProperties,
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
      },
    };
  }

  //get analytics about out sold out rented out for each month
  async getPropertyAnalyticForBroker(id: string) {
    const currentDate = new Date();
    const currentYear = currentDate.getFullYear();
    const currentMonth = currentDate.getMonth() + 1;

    const startMonth = currentMonth;
    const startYear = currentYear - 1;

    const monthYearPairs = [];
    for (let year = startYear; year <= currentYear; year++) {
      const endMonth = year === currentYear ? currentMonth : 12; // Include current month if it's the current year
      for (let month = 1; month <= endMonth; month++) {
        if (year === startYear && month < startMonth) {
          continue;
        }
        monthYearPairs.push({ year, month });
      }
    }
    //for sold properties
    const soldProperties = await this.PropertyModel.aggregate([
      {
        $match: {
          broker: new mongoose.Types.ObjectId(id),
          isSoldOut: true,
          isDeleted: false,
          // rentedDays: { $ne: [] },
          updatedAt: {
            $gte: new Date(`${startYear}-${startMonth}-01`),
            $lte: new Date(`${currentYear}-${currentMonth}-31T23:59:59.999Z`),
          },
        },
      },
      {
        $group: {
          _id: {
            year: { $year: '$updatedAt' },
            month: { $month: '$updatedAt' },
          },
          total: { $sum: 1 }, // Count the number of rented properties
        },
      },
      {
        $project: {
          _id: 0, // Exclude _id field
          monthYear: {
            $dateToString: {
              format: '%Y-%m', // Format as 'YYYY-MM'
              date: {
                $dateFromParts: {
                  year: '$_id.year',
                  month: '$_id.month',
                  day: 1, // Assuming day as 1, you can adjust as needed
                },
              },
            },
          },
          total: 1,
        },
      },
      {
        $sort: { monthYear: 1 },
      },
    ]);
    // for rented properties
    const rentedProperties = await this.PropertyModel.aggregate([
      {
        $match: {
          broker: new mongoose.Types.ObjectId(id),
          isRented: true,
          // rentedDays: { $ne: [] },
          updatedAt: {
            $gte: new Date(`${startYear}-${startMonth}-01`),
            $lte: new Date(`${currentYear}-${currentMonth}-31T23:59:59.999Z`),
          },
        },
      },
      {
        $group: {
          _id: {
            year: { $year: '$updatedAt' },
            month: { $month: '$updatedAt' },
          },
          total: { $sum: 1 }, // Count the number of rented properties
        },
      },
      {
        $project: {
          _id: 0, // Exclude _id field
          monthYear: {
            $dateToString: {
              format: '%Y-%m', // Format as 'YYYY-MM'
              date: {
                $dateFromParts: {
                  year: '$_id.year',
                  month: '$_id.month',
                  day: 1, // Assuming day as 1, you can adjust as needed
                },
              },
            },
          },
          total: 1,
        },
      },
      {
        $sort: { monthYear: 1 },
      },
    ]);
    // console.log(rentedProperties);
    // Create an array with 12 items, initializing each month's total to 0
    const monthlyTotalsSoldProperties = monthYearPairs.map(
      ({ year, month }) => {
        const monthString = `${year}-${month.toString().padStart(2, '0')}`;
        const matchingItem = soldProperties.find(
          (item) => item.monthYear === monthString,
        );
        return {
          month: monthString + '-10', // Adjust the month as needed
          total: matchingItem ? matchingItem.total : 0,
        };
      },
    );
    const monthlyTotalsRentedProperties = monthYearPairs.map(
      ({ year, month }) => {
        const monthString = `${year}-${month.toString().padStart(2, '0')}`;
        const matchingItem = rentedProperties.find(
          (item) => item.monthYear === monthString,
        );
        return {
          month: monthString + '-10', // Adjust the month as needed
          total: matchingItem ? matchingItem.total : 0,
        };
      },
    );

    return { monthlyTotalsSoldProperties, monthlyTotalsRentedProperties };
  }

  // get graph property analytics for brokers

  //*-----------------------starting from this line the apis are for brokers and admin shared section-------------------*
  //property detail for admin and broker
  async propertyDetail(id: string): Promise<any> {
    const isPropertyExist = await this.PropertyModel.findById(id)
      .populate('owner')
      .populate('broker')
      .populate('poster')
      .populate({
        path: 'agent',
        populate: {
          path: 'user',
        },
      })
      .populate('facilities.facility')
      .populate('amenities')
      .populate('propertyHomeType');
    if (!isPropertyExist) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    const propertyRating = await this.ratingService.getPropertyRates(id);
    return await { property: isPropertyExist, propertyRating };
  }
  //make it rented out or sold out
  async makePropertyRentedOrSoldOut(id: string) {
    const property = await this.PropertyModel.findById(id);
    if (!property) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    if (property.isSoldOut) {
      throw new HttpException(
        'Property is Already Sold Out',
        HttpStatus.NOT_FOUND,
      );
    }
    if (property.isRented) {
      throw new HttpException(
        'Property is Already Rented',
        HttpStatus.NOT_FOUND,
      );
    }
    if (property.propertyType == PropertyTypes.rent) {
      const makeItRentedOut = await this.PropertyModel.findByIdAndUpdate(
        id,
        { $set: { isRented: true, $push: { rentedDays: new Date() } } },
        { new: true },
      );
      return makeItRentedOut;
    } else {
      //its type is sale
      const makeItSoldOut = await this.PropertyModel.findByIdAndUpdate(
        id,
        { $set: { isSoldOut: true } },
        { new: true },
      );
      return makeItSoldOut;
    }
  }

  //make rented one back to normal bg admin broker or agent
  async makeRentedPropertyBack(id: string) {
    const property = await this.PropertyModel.findById(id);
    if (!property) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    if (!property.isRented) {
      throw new HttpException('Property is Not Rented', HttpStatus.NOT_FOUND);
    }
    const makeItRentedOut = await this.PropertyModel.findByIdAndUpdate(
      id,
      { $set: { isRented: false } },
      { new: true },
    );
    return makeItRentedOut;
  }

  //delete property by admin or broker or agent(based on his permission)
  async deleteProperty(id: string): Promise<any> {
    const isPropertyExist = await this.PropertyModel.findByIdAndUpdate(
      id,
      {
        $set: { isDeleted: true },
      },
      { new: true },
    );
    if (!isPropertyExist) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    await this.PropertyModel.findByIdAndDelete(id);
    return 'property deleted successfully';
  }
  //delete image from cloudinary and from property
  async deletePropertyImage(id: string, imageId: string) {
    const propertyImages = await this.PropertyModel.findById(id);
    if (!propertyImages) {
      throw new HttpException('Property Not Found', HttpStatus.NOT_FOUND);
    }
    //find the images from the property image bu authorized broker and admin
    const images = propertyImages.images?.find(
      (image: any) => image._id.toString() == imageId,
    );
    if (!images) {
      throw new HttpException('Image Not Found', HttpStatus.NOT_FOUND);
    }
    await this.PropertyModel.findByIdAndUpdate(
      id,
      { $pull: { images: { _id: imageId } } },
      { new: true },
    );
    return 'Image Deleted Successfully';
  }
}
