import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Ads } from './schema/ad.schema';
import { Model } from 'mongoose';
import {
  CreateAdsByAdminDto,
  CreateAdsDto,
  UpdateAdsDto,
} from './dto/create-ads.dt';
import { PaymentService } from 'src/payment/payment.service';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { PaginationService } from 'src/services/pagination.service';
import { AdsBannerStatus } from 'src/utils/status.enum';
import { AdsAction } from 'src/utils/actions.enum';
import { AdsFilterType } from 'src/utils/filter.enum';

@Injectable()
export class AdsService {
  constructor(
    @InjectModel(Ads.name) private adsModel: Model<Ads>,
    private paymentService: PaymentService,
    private readonly cloudinaryService: CloudinaryService,
    private readonly paginationService: PaginationService,
  ) {}
  // get all active ads count
  async getAdsCountForBroker(id: string) {
    const adsCount = await this.adsModel.countDocuments({
      broker: id,
      status: AdsBannerStatus.APPROVED,
    });
    return adsCount;
  }
  //create new ad banner
  async createAds(data: CreateAdsDto, image: Express.Multer.File) {
    const newAds = await this.paymentService.makePaymentForAdsBanner(data);
    const imageUrl = await this.cloudinaryService.uploadFile(image);
    const createNewAds = await this.adsModel.create({
      title: data.title,
      startDate: data.startDate,
      endDate: data.endDate,
      payment: newAds._id,
      owner: data.owner,
      broker: data.broker,
      image: imageUrl.secure_url,
    });
    const ads = await this.adsModel
      .findById(createNewAds._id)
      .populate('broker');
    return { data: ads, type: AdsAction.CREATE };
  }

  //create ad by broker
  //create new ad banner
  async createAdminAds(data: CreateAdsByAdminDto, image: Express.Multer.File) {
    const imageUrl = await this.cloudinaryService.uploadFile(image);
    const createNewAds = await this.adsModel.create({
      title: data.title,
      startDate: data.startDate,
      endDate: data.endDate,
      image: imageUrl.secure_url,
      isInHouseAd: true,
      isApproved: true,
      status: AdsBannerStatus.APPROVED,
    });

    return createNewAds;
  }

  //get all ads the end date is less than today
  async getAllAdsForUser() {
    const currentDate = new Date();
    const allAds = await this.adsModel
      .find({
        endDate: { $gte: currentDate }, // Filter ads with end date less than current date
        isApproved: true,
        status: AdsBannerStatus.APPROVED,
      })
      .select('_id title image');
    return allAds;
  }
  //get ads of single broker
  async getBrokerAds(id: string) {
    const currentDate = new Date();
    return await this.adsModel.find({
      endDate: { $gte: currentDate }, // Filter ads with end date less than current date
      isApproved: true,
      status: AdsBannerStatus.APPROVED,
      broker: id,
    });
  }

  //get admin ads
  async getInHouseAds() {
    const currentDate = new Date();
    return await this.adsModel.find({
      endDate: { $gte: currentDate }, // Filter ads with end date less than current date
      isApproved: true,
      status: AdsBannerStatus.APPROVED,
      broker: null,
    });
  }

  //get ads by owner used by property service
  async getAdsByOwner(id: string) {
    const currentDate = new Date();
    return await this.adsModel.find({
      endDate: { $gte: currentDate }, // Filter ads with end date less than current date
      isApproved: true,
      status: AdsBannerStatus.APPROVED,
      owner: id,
    });
  }
  //*******************Broker End Point **************** */
  //get all ads for broker
  async getAllAdsForBroker(page: number, perPage: number, id: string) {
    const allAds = await this.adsModel.find({ broker: id }).populate('payment');
    const totalAds = allAds.length;
    const paginatedData = this.paginationService.paginate(
      allAds,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalAds,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalAds,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
  //update and re post ads or rejected ads
  async updateAdsByBroker(
    id: string,
    data: UpdateAdsDto,
    image: Express.Multer.File,
  ) {
    const isAdsExist = await this.adsModel.findById(id);
    if (!isAdsExist) {
      throw new HttpException('Ads Not Found', HttpStatus.NOT_FOUND);
    }
    const imageUrl = await this.cloudinaryService.uploadFile(image);
    const updateAds = await this.adsModel.findByIdAndUpdate(
      id,
      {
        title: data.title,
        startDate: data.startDate,
        endDate: data.endDate,
        image: imageUrl.secure_url,
        isEdited: true,
        isApproved: false,
        isRejected: false,
      },
      { new: true },
    );
    return updateAds;
  }

  //get ads details by broker
  async getAdsDetailsByBroker(id: string) {
    const isAdsExist = await this.adsModel.findById(id);
    if (!isAdsExist) {
      throw new HttpException('Ads Not Found', HttpStatus.NOT_FOUND);
    }
    const adsDetails = await this.adsModel
      .findById(id)
      .populate('payment')
      .populate({ path: 'payment.user' })
      .populate('owner');
    return adsDetails;
  }

  //******************* admin end point ***********************/
  //get all ads for admin
  async getAdsCount() {
    const adsCount = await this.adsModel.countDocuments();
    return adsCount;
  }
  async getAllAdsForAdmin(page: number, perPage: number, type: AdsFilterType) {
    const commonQuery = {};
    if (type === AdsFilterType.InHouses) {
      commonQuery['broker'] = null;
    } else if (type === AdsFilterType.Brokers) {
      commonQuery['isInHouseAd'] = false;
    } else if (type === AdsFilterType.All) {
    }
    const allAds = await this.adsModel
      .find(commonQuery)
      .populate('broker')
      .sort({ createdAt: -1 });
    const totalAds = allAds.length;
    const paginatedData = this.paginationService.paginate(
      allAds,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalAds,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalAds,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
  //get all ads of brokers for admin
  async getAllBrokerAdsForAdmin(
    page: number,
    perPage: number,
    type: AdsFilterType,
  ) {
    const commonQuery = {};
    if (type === AdsFilterType.InHouses) {
      commonQuery['broker'] = null;
      commonQuery['isInHouseAd'] = false;
    } else if (type === AdsFilterType.Brokers) {
      commonQuery['isInHouseAd'] = false;
    } else if (type === AdsFilterType.All) {
      commonQuery['isInHouseAd'] = false;
    }
    const allAds = await this.adsModel
      .find({ isInHouseAd: false })
      .populate('broker')
      .sort({ createdAt: -1 });
    const totalAds = allAds.length;
    const paginatedData = this.paginationService.paginate(
      allAds,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalAds,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalAds,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
  //approve ads
  async approveAdsByAdmin(id: string) {
    const isAdExist = await this.adsModel.findById(id);
    if (!isAdExist) {
      throw new HttpException('Ads Not Found', HttpStatus.NOT_FOUND);
    }
    const ads = await this.adsModel.findByIdAndUpdate(
      id,
      { isApproved: true, status: AdsBannerStatus.APPROVED },
      { new: true },
    );
    //approve payment also
    await this.paymentService.approvePayment(ads.payment.toString());
    return { data: ads, type: AdsAction.APPROVE };
  }

  //reject ads by admin
  async rejectAdsByAdmin(id: string) {
    const isAdExist = await this.adsModel.findById(id);
    if (!isAdExist) {
      throw new HttpException('Ads Not Found', HttpStatus.NOT_FOUND);
    }
    const ads = await this.adsModel.findByIdAndUpdate(
      id,
      { isRejected: true },
      { new: true },
    );
    return ads;
  }
  //******************* common end point end point ***********************/
  //delete ads
  async deletedAd(id: string) {
    const isAdExist = await this.adsModel.findById(id);
    if (!isAdExist) {
      throw new HttpException('Ads Not Found', HttpStatus.NOT_FOUND);
    }
    await this.adsModel.findByIdAndDelete(id);
    return 'ads deleted successfully';
  }
}
