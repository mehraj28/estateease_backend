import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Broker } from './schema/broker.schema';
import { Model } from 'mongoose';
import { PaginationService } from 'src/services/pagination.service';
import { CreateBrokerDto, UpdateBrokerDto } from './dto/create-broker.dto';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';

@Injectable()
export class BrokersService {
  constructor(
    @InjectModel(Broker.name) private brokerModel: Model<Broker>,
    private readonly paginationService: PaginationService,
    private readonly cloudinaryService: CloudinaryService,
  ) {}

  //get free listing qota of broker
  async getFreeQoataOfBroker(id: string) {
    return await this.brokerModel.findById(id);
  }

  //create broker service used by other module
  async createBroker(createBrokerDto: CreateBrokerDto) {
    return await this.brokerModel.create(createBrokerDto);
  }
  async getBrokersCount() {
    return await this.brokerModel.countDocuments();
  }
  //get all brokers for admin
  async getAllBrokers(page: number, perPage: number) {
    const allBrokers = await this.brokerModel.find({});
    const totalBrokers = allBrokers.length;
    const paginatedData = this.paginationService.paginate(
      allBrokers,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalBrokers,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalBrokers,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
  //get single broker by id
  async getBrokerById(id: string) {
    const broker = await this.brokerModel.findById(id);
    if (!broker) {
      throw new HttpException('broker not found', HttpStatus.NOT_FOUND);
    }
    return broker;
  }

  //substract free listing qoata
  async substractFreeListingQuota(brokerId: string) {
    const broker = await this.brokerModel.findById(brokerId);
    if (!broker) {
      throw new HttpException('broker not found', HttpStatus.NOT_FOUND);
    }
    if (broker.freeListingQuotaRemaining > 0) {
      broker.freeListingQuotaRemaining -= 1;
      broker.save();
    }
  }

  //update company information
  async updateCompanyInfo(
    id: string,
    data: UpdateBrokerDto,
    logo: Express.Multer.File,
    coverImage: Express.Multer.File,
  ) {
    let newLogo: string;
    let coverPhoto: string | null;
    const broker = await this.brokerModel.findById(id);
    if (!broker) {
      throw new HttpException(
        'Broker Company Does not Exist',
        HttpStatus.NOT_FOUND,
      );
    }
    if (logo) {
      const imageUrl = await this.cloudinaryService.uploadFile(logo[0]);
      newLogo = imageUrl.secure_url;
    }
    if (coverImage) {
      const imageUrl = await this.cloudinaryService.uploadFile(coverImage[0]);
      coverPhoto = imageUrl.secure_url;
    }
    //update company info
    if (newLogo) {
      await this.brokerModel.findByIdAndUpdate(
        id,
        { $set: { ...data, logo: newLogo, coverImage: coverPhoto } },
        { new: true },
      );

      return 'company profile updated successfully';
    }
    await this.brokerModel.findByIdAndUpdate(
      id,
      { $set: { ...data, coverImage: coverPhoto } },
      { new: true },
    );
    return 'company profile updated successfully';
  }
}
