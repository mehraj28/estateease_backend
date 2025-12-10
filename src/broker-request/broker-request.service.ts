import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { BrokerRequest } from './schema/broker-request-schema';
import { Model } from 'mongoose';
import {
  AcceptRequestDto,
  RejectRequestDto,
  SendRequestDto,
} from './dto/send-request.dto';
import { User } from 'src/users/schema/user.schema';
import { BrokerRequestStatus } from 'src/utils/status.enum';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { PaginationService } from 'src/services/pagination.service';
import { BrokersService } from 'src/brokers/brokers.service';
import { AgentsService } from 'src/agents/agents.service';
import { UsersService } from 'src/users/users.service';
import { Role } from 'src/utils/role.enum';
import { BrokerRequestAction } from 'src/utils/actions.enum';
import { MailService } from 'src/services/mail.service';

@Injectable()
export class BrokerRequestService {
  constructor(
    @InjectModel(BrokerRequest.name)
    private brokerRequestModel: Model<BrokerRequest>,
    @InjectModel(User.name)
    private userModel: Model<User>,
    private readonly cloudinaryService: CloudinaryService,
    private readonly paginationService: PaginationService,
    private readonly brokersService: BrokersService,
    private readonly agentsService: AgentsService,
    private readonly usersService: UsersService,
    private readonly mailService: MailService,
  ) {}

  // receive broker request
  async sendRequest(data: SendRequestDto, logo: Express.Multer.File) {
    //first check if the user is verified and exist
    const isUserExist = await this.userModel
      .findById(data.user)
      .select('hasFullInfo');
    if (!isUserExist || !isUserExist.hasFullInfo)
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    //check if the user is already broker or not
    if (isUserExist.broker)
      throw new HttpException('You have company already', HttpStatus.NOT_FOUND);
    //check if the user has unfinished request before
    const hasUserMadeRequest = await this.brokerRequestModel.findOne({
      $and: [
        {
          user: data.user,
          $or: [
            {
              status: BrokerRequestStatus.APPROVED,
            },
            {
              status: BrokerRequestStatus.PENDING,
            },
          ],
        },
      ],
    });
    if (hasUserMadeRequest)
      throw new HttpException(
        'You have already sent request please wait until we review your request',
        HttpStatus.FAILED_DEPENDENCY,
      );
    //check the broker name is exist
    const isNameUnique = await this.brokerRequestModel.findOne({
      $and: [
        {
          companyName: data.companyName,
          $or: [
            {
              status: BrokerRequestStatus.APPROVED,
            },
            {
              status: BrokerRequestStatus.PENDING,
            },
          ],
        },
      ],
    });
    if (isNameUnique)
      throw new HttpException(
        'company name already exist',
        HttpStatus.CONFLICT,
      );
    //check the broker phone is exist
    const isPhoneUnique = await this.brokerRequestModel.findOne({
      $and: [
        {
          phone: data.phone,
          $or: [
            {
              status: BrokerRequestStatus.APPROVED,
            },
            {
              status: BrokerRequestStatus.PENDING,
            },
          ],
        },
      ],
    });
    if (isPhoneUnique)
      throw new HttpException(
        'company Phone already exist',
        HttpStatus.CONFLICT,
      );
    //check if user previous request is rejected or not then if rejected update the request
    const isUserRequestRejected = await this.brokerRequestModel.findOne({
      user: data.user,
      status: BrokerRequestStatus.REJECTED,
    });
    const imageUrl = await this.cloudinaryService.uploadFile(logo);
    if (isUserRequestRejected) {
      const updateBrokerRequest =
        await this.brokerRequestModel.findOneAndUpdate(
          {
            user: data.user,
          },
          {
            $set: {
              ...data,
              logo: imageUrl.secure_url,
              status: BrokerRequestStatus.PENDING,
            },
          },
          { new: true },
        );
      return updateBrokerRequest;
    }
    //since user hasn't make request before create new one
    const newRequest = await this.brokerRequestModel.create({
      ...data,
      logo: imageUrl.secure_url,
    });
    return { data: newRequest, type: BrokerRequestAction.CREATE };
  }

  // get all brokers request for admin
  async getAllRequest(page: number, perPage: number) {
    const allRequests = await this.brokerRequestModel
      .find()
      .sort({ createdAt: -1 });
    const totalRequests = allRequests.length;
    const paginatedData = this.paginationService.paginate(
      allRequests,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalRequests,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalRequests,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
  //accept brokers request by admin
  async acceptBrokersRequest(data: AcceptRequestDto, id: string) {
    //check if the request is new
    const brokerRequest = await this.brokerRequestModel.findById(id);
    if (!brokerRequest) {
      throw new HttpException('Request Does not Exist', HttpStatus.NOT_FOUND);
    }
    if (brokerRequest.status !== BrokerRequestStatus.PENDING) {
      throw new HttpException(
        'This Request is can not be accepted',
        HttpStatus.FAILED_DEPENDENCY,
      );
    }
    //accept the request
    await this.brokerRequestModel.findByIdAndUpdate(
      id,
      {
        $set: { status: BrokerRequestStatus.APPROVED, isApproved: true },
      },
      { new: true },
    );
    //create Broker company for the accepted request
    const newBrokerCompany = await this.brokersService.createBroker({
      name: brokerRequest.companyName,
      logo: brokerRequest.logo,
      address: brokerRequest.address,
      phone: brokerRequest.phone,
      email: brokerRequest.email,
      freeListingQuota: data.freeListingQuota ?? 0,
      freeListingQuotaRemaining: data.freeListingQuotaRemaining ?? 0,
    });

    //create the broker as agent automatically
    await this.agentsService.createAgent({
      broker: newBrokerCompany?._id,
      user: brokerRequest.user,
    });

    // finally update user to make its role rom User To Broker
    await this.userModel.findByIdAndUpdate(
      brokerRequest.user,
      { $set: { broker: newBrokerCompany._id, role: Role.Broker } },
      { new: true },
    );
    return {
      data: brokerRequest,
      type: BrokerRequestAction.APPROVE,
    };
  }

  // reject brokers request
  async rejectBrokersRequest(id: string, data: RejectRequestDto) {
    //check if the request is new
    const brokerRequest = await this.brokerRequestModel.findById(id);
    if (!brokerRequest) {
      throw new HttpException('Request Does not Exist', HttpStatus.NOT_FOUND);
    }
    if (brokerRequest.status !== BrokerRequestStatus.PENDING) {
      throw new HttpException(
        'This Request is can not be accepted, its status is already changed',
        HttpStatus.FAILED_DEPENDENCY,
      );
    }
    //reject brokers request
    const rejectRequest = await this.brokerRequestModel.findByIdAndUpdate(
      id,
      {
        $set: { status: BrokerRequestStatus.REJECTED },
      },
      { new: true },
    );
    //send notification to user why his request is rejected by interceptor
    return {
      data: { rejectRequest, message: data.message },
      type: BrokerRequestAction.REJECT,
    };
  }
  //get own request status info
  async getOwnRequestInfo(id: string) {
    //first check if the user is verified and exist
    const isUserExist = await this.userModel.findById(id);
    if (!isUserExist)
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    //check if the user made a request or not
    const hasMadeRequest = await this.brokerRequestModel.findOne({
      user: id,
      $or: [
        { status: BrokerRequestStatus.PENDING },
        { status: BrokerRequestStatus.APPROVED },
        { status: BrokerRequestStatus.REJECTED },
      ],
    });
    return hasMadeRequest;
  }

  //reqiuest detail
  async brokerRequestDetail(id: string) {
    const request = (await this.brokerRequestModel.findById(id)).populate(
      'user',
    );
    if (!request)
      throw new HttpException('Request not found', HttpStatus.NOT_FOUND);
    return request;
  }
}
