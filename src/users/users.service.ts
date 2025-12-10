import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { Model } from 'mongoose';
import { FinishSignUpDto } from 'src/auth/dto/signup.dto';
import { Role } from 'src/utils/role.enum';
import { PaginationService } from 'src/services/pagination.service';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private readonly paginationService: PaginationService,
    private readonly cloudinaryService: CloudinaryService,
  ) {}
  //find user by its ID
  async findUserById(id: string): Promise<any> {
    return await this.userModel.findById(id).select('+password');
  }
  //find user by its Email
  async findUserByEmail(email: string): Promise<any> {
    return await this.userModel.findOne({ email }).select('+password');
  }
  // find verified user
  async findVerifiedUserByEmail(email: string): Promise<any> {
    return await this.userModel.findOne({
      email,
      isVerified: true,
      hasFullInfo: false,
    });
  }

  async findHasFullInfoUserByEmail(email: string): Promise<any> {
    return await this.userModel.findOne({
      email,
      isVerified: true,
      hasFullInfo: true,
    });
  }
  //update the verified method once otp is verified
  async updateVerifiedMethod(email: string): Promise<any> {
    return await this.userModel.findOneAndUpdate(
      { email },
      { isVerified: true },
      { new: true },
    );
  }
  //update has full info once user has completed his registration
  async updatehasFullInfoMethod(email: string): Promise<any> {
    return await this.userModel.findOneAndUpdate(
      { email },
      { hasFullInfo: true },
      { new: true },
    );
  }
  //find user by its Email
  async findUserForForgotPassword(email: string): Promise<any> {
    return await this.userModel.findOne({ email });
  }
  //find user by phone
  async findUserByPhone(phone: string): Promise<any> {
    return await this.userModel.findOne({ phone });
  }
  //populate some info of user
  async populateUserInfo(model: any, path: string) {
    return await this.userModel.populate(model, { path: path });
  }
  //find user by brokerId
  async findUserByBrokerId(brokerId: string): Promise<any> {
    return await this.userModel.findOne({ broker: brokerId });
  }
  //find all admin and return their email
  async findAllAdmins(): Promise<any> {
    return (
      await this.userModel.find({ role: Role.Admin }).select('email')
    ).map((user) => user._id);
  }

  //find all admin email to send email notifications
  async findAllAdminsEmail(): Promise<any> {
    return (
      await this.userModel.find({ role: Role.Admin }).select('email')
    ).map((user) => user.email);
  }
  //get user email by broker id
  async getUserEmailByBrokerId(brokerId: string): Promise<any> {
    return await this.userModel.findOne({ broker: brokerId }).select('email');
  }

  //get user email by user id
  async getUserEmailByUserId(userId: string): Promise<any> {
    return await this.userModel.findById(userId).select('email');
  }

  //get user by broker id
  async getUserByBrokerId(brokerId: string): Promise<any> {
    return await this.userModel.findOne({ broker: brokerId });
  }
  async getUsersCount() {
    return await this.userModel.countDocuments();
  }
  //create new user this is used by other services
  async createNewAgent(createAgentDto: FinishSignUpDto): Promise<any> {
    return await this.userModel.create({
      firstName: createAgentDto.firstName,
      lastName: createAgentDto.lastName,
      email: createAgentDto.email,
      phone: createAgentDto.phone,
      password: createAgentDto.password,
      role: Role.Agent,
      permissions: createAgentDto.permissions,
    });
  }

  //get my profile
  async getMyProfile(id: string) {
    const user = await this.userModel.findById(id);
    if (!user) {
      throw new HttpException('User Does not Exist', HttpStatus.NOT_FOUND);
    }
    return user;
  }
  async updateMyProfile(
    data: UpdateProfileDto,
    image: Express.Multer.File,
    id: string,
  ) {
    const user = await this.userModel.findById(id);
    if (!user) {
      throw new HttpException('User Does not Exist', HttpStatus.NOT_FOUND);
    }
    if (image) {
      const imageUrl = await this.cloudinaryService.uploadFile(image);
      const updateProfile = await this.userModel.findByIdAndUpdate(
        id,
        { $set: { ...data, profile_image: imageUrl.secure_url } },
        { new: true },
      );
      return updateProfile;
    }
    const updateProfile = await this.userModel.findByIdAndUpdate(
      id,
      { $set: { ...data } },
      { new: true },
    );
    return updateProfile;
  }

  // ------------------admin end points----------------------//
  async getAllEndUsers(page: number, perPage: number) {
    const allUsers = await this.userModel.find({
      // role: Role.User,
    });
    const totalUsers = allUsers.length;
    const paginatedData = this.paginationService.paginate(
      allUsers,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalUsers,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalUsers,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
}
