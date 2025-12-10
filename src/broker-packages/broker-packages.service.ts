import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { BrokerPackage } from './schema/broker-package.schema';
import { Model } from 'mongoose';
import { CreateBrokerPackageDto } from './dto/create-broker-package.dto';
import { PaymentService } from 'src/payment/payment.service';
import { PackagesService } from 'src/packages/packages.service';
import { ListingQuotaStatus } from 'src/utils/status.enum';
import { PaginationService } from 'src/services/pagination.service';
import { ListingPackageAction } from 'src/utils/actions.enum';
import { BrokersService } from 'src/brokers/brokers.service';

@Injectable()
export class BrokerPackagesService {
  constructor(
    @InjectModel(BrokerPackage.name)
    private brokerPackageModel: Model<BrokerPackage>,
    private readonly paymentService: PaymentService,
    private readonly packagesService: PackagesService,
    private readonly paginationService: PaginationService,
    private readonly brokerService: BrokersService,
  ) {}

  //get total package of broker used by other module like anlaytics
  async totalPackagesOfBroker(id: string) {
    return this.brokerPackageModel.find().countDocuments({ broker: id });
  }
  ///************broker end points********** */
  //buy broker package
  async buyListingPackage(
    data: CreateBrokerPackageDto,
  ): Promise<{ data: BrokerPackage; type: ListingPackageAction }> {
    const ownedPackage = await this.packagesService.getPackageById(
      data.package,
    );
    const payment = await this.paymentService.makePaymentForListingPackage(
      data,
    );
    const brokerPackage = await this.brokerPackageModel.create({
      package: ownedPackage,
      broker: data.broker,
      payment: payment._id,
      user: data.user,
    });
    const buyedPackage = await this.brokerPackageModel
      .findById(brokerPackage._id)
      .populate('broker');
    return { data: buyedPackage, type: ListingPackageAction.CREATE };
  }
  //get my active packages
  async getMyActivePackages(brokerId: string) {
    const myActivePackages = await this.brokerPackageModel
      .findOne({
        broker: brokerId,
        isActive: true,
      })
      .populate('broker')
      .sort({ createdAt: -1 })
      .select('package status isActive');
    //get the user free listing quota if he has
    const brokerFreeQuota = await this.brokerService.getFreeQoataOfBroker(
      brokerId,
    );
    if (brokerFreeQuota?.freeListingQuotaRemaining < 1) {
      return myActivePackages || brokerFreeQuota;
    } else {
      return brokerFreeQuota;
    }
  }

  //chek if the user has free listing qouta or ha package or not

  //substraction of listing quota whn property is listed and if quota is zero then deactivate the package and if there is approved package but not activated activate that package
  async substractListingQuota(brokerId: string) {
    //first check if the broker has free quota or not
    const broker = await this.brokerService.getBrokerById(brokerId);
    if (broker?.freeListingQuotaRemaining > 0) {
      await this.brokerService.substractFreeListingQuota(brokerId);
      return;
    }

    // if(broker)
    const activePackage = await this.brokerPackageModel.findOne({
      broker: brokerId,
      isActive: true,
      status: ListingQuotaStatus.APPROVED,
    });
    if (activePackage) {
      if (activePackage.package.remining >= 1) {
        const updatedPackage = await this.brokerPackageModel.findByIdAndUpdate(
          activePackage._id,
          {
            $inc: {
              'package.remining': -1,
            },
          },
          { new: true },
        );
        // console
        if (updatedPackage.package.remining < 1) {
          await this.brokerPackageModel.findByIdAndUpdate(
            updatedPackage._id,
            {
              $set: {
                isActive: false,
                status: ListingQuotaStatus.STOPPED,
              },
            },
            { new: true },
          );
          //activate if there is approved package but not activated
          const approvedPackage = await this.brokerPackageModel.findOne({
            broker: brokerId,
            isActive: false,
            status: ListingQuotaStatus.APPROVED,
          });
          if (approvedPackage) {
            await this.brokerPackageModel.findByIdAndUpdate(
              approvedPackage._id,
              { $set: { isActive: true } },
              { new: true },
            );
          }
        }
      }
    }
    return 'All process are done';
  }
  //*********************admin end points**************** */
  //get all listing requets
  async getAllListingRequests(page: number, perPage: number) {
    const allListingRequests = await this.brokerPackageModel
      .find({})
      .populate('broker')
      .populate('payment');

    const totalPackages = allListingRequests.length;
    const paginatedData = this.paginationService.paginate(
      allListingRequests,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalPackages,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalPackages,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }

  //get single listing request
  async getSingleListingRequest(id: string) {
    const listingRequest = await this.brokerPackageModel
      .findById(id)
      .populate('broker')
      .populate('user')
      .populate('payment');
    if (!listingRequest) {
      throw new HttpException(
        'listing package not found',
        HttpStatus.BAD_REQUEST,
      );
    }
    return listingRequest;
  }
  //approve listing package
  async approveListingRequestPackage(
    id: string,
  ): Promise<{ data: BrokerPackage; type: ListingPackageAction }> {
    let updatedListingPackage: BrokerPackage;
    const listingPackage = await this.brokerPackageModel.findById(id);
    if (!listingPackage) {
      throw new HttpException('Invalid Id', HttpStatus.BAD_REQUEST);
    }
    //check if the broker has already an active package
    const activePackage = await this.brokerPackageModel.findOne({
      broker: listingPackage.broker,
      isActive: true,
      status: ListingQuotaStatus.APPROVED,
    });
    await this.paymentService.approvePayment(listingPackage.payment.toString());
    if (activePackage) {
      updatedListingPackage = await this.brokerPackageModel.findByIdAndUpdate(
        id,
        {
          $set: {
            status: ListingQuotaStatus.APPROVED,
          },
        },
        { new: true },
      );
    } else {
      updatedListingPackage = await this.brokerPackageModel.findByIdAndUpdate(
        id,
        {
          $set: {
            isActive: true,
            status: ListingQuotaStatus.APPROVED,
          },
        },
        { new: true },
      );
    }

    return { data: updatedListingPackage, type: ListingPackageAction.APPROVE };
  }

  //==================brokers end point=================//
  async getAllListingPackagesForBroker(
    page: number,
    perPage: number,
    id: string,
  ) {
    const allListingRequests = await this.brokerPackageModel
      .find({
        broker: id,
      })
      .populate('payment');

    const totalPackages = allListingRequests.length;
    const paginatedData = this.paginationService.paginate(
      allListingRequests,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalPackages,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalPackages,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
}
