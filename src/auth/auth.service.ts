import {
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { DashboardLoginDto, LoginDto } from './dto/login.dto';
import {
  comparePassword,
  hashedOtpOrPassword,
} from 'src/helpers/password.validator';
import { JwtService } from '@nestjs/jwt';
import {
  FinishRegistrationDto,
  SignUpDto,
  VerifyOtpDto,
} from './dto/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from 'src/users/schema/user.schema';
import { Model } from 'mongoose';
import { Role } from 'src/utils/role.enum';
import { MailService } from 'src/services/mail.service';
import {
  ForgotPasswordDto,
  VerifyOtpForgotPasswordDto,
  SetNewPasswordDto,
  ChangePasswordDto,
} from './dto/forgot-password.dto';
import { OtpService } from 'src/otp/otp.service';
@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private userService: UsersService,
    private jwtService: JwtService,
    private readonly mailService: MailService,
    private readonly otpService: OtpService,
  ) {}

  //initial create admin account
  async createAdminAccount(data: FinishRegistrationDto) {
    const user = await this.userService.findUserByEmail(data.email);
    if (user) {
      throw new HttpException('User Already Exist', HttpStatus.BAD_REQUEST);
    }
    //hash password
    const hashPassword = await hashedOtpOrPassword(data.password);
    const newUser = await this.userModel.create({
      ...data,
      password: hashPassword,
      role: Role.Admin,
      hasFullInfo: true,
      isVerified: true,
    });
    const token = this.jwtService.sign({
      id: newUser._id,
      role: newUser.role,
      permission: newUser.permissions,
    });
    return { user: newUser, token: token };
  }

  //create admin account by param
  async createIntialAdminAccount(email: string) {
    if (!email) {
      throw new HttpException(
        'Please Provide Email Address',
        HttpStatus.BAD_REQUEST,
      );
    }
    const user = await this.userService.findUserByEmail(email);
    if (user) {
      throw new HttpException('User Already Exist', HttpStatus.BAD_REQUEST);
    }
    //hash password
    const hashPassword = await hashedOtpOrPassword('password');
    const newUser = await this.userModel.create({
      firstName: 'Admin',
      lastName: 'User',
      email,
      password: hashPassword,
      role: Role.Admin,
      hasFullInfo: true,
      isVerified: true,
    });

    return { user: newUser, message: 'Account created Successfully' };
  }
  async dashboardLogin(data: DashboardLoginDto): Promise<any> {
    const user = await this.userService.findUserByEmail(data.email);
    if (!user) {
      throw new HttpException('User Not Found', HttpStatus.NOT_FOUND);
    }
    if (user.role == Role.User || user.role == Role.Agent) {
      throw new HttpException('User Not Found', HttpStatus.NOT_FOUND);
    }
    // check if password is correct
    const isPasswordMatched = await comparePassword(
      data.password,
      user.password,
    );
    if (!isPasswordMatched) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const token = this.jwtService.sign({
      id: user._id,
      role: user.role,
      permission: user.permissions,
    });
    return { user: user, token: token };
  }
  //login for mobile app side
  async userLogin(data: LoginDto): Promise<any> {
    const user = await this.userService.findUserByEmail(data.email);
    if (!user) {
      throw new HttpException('User Not Found', HttpStatus.NOT_FOUND);
    }
    // check if password is correct
    const isPasswordMatched = await comparePassword(
      data.password,
      user.password,
    );
    if (!isPasswordMatched) {
      throw new UnauthorizedException('Invalid email or password');
    }
    const userWithDeviceId = await this.userModel.findByIdAndUpdate(
      user.id,
      {
        $set: { deviceId: data.deviceId },
      },
      { new: true },
    );
    const token = this.jwtService.sign({
      id: user._id,
      role: user.role,
      permission: user.permissions,
    });
    return { user: userWithDeviceId, token: token };
  }

  // ==========================sign up flow ================================//
  async signUp(data: SignUpDto): Promise<any> {
    const user = await this.userService.findHasFullInfoUserByEmail(data.email);
    if (user) {
      throw new HttpException('User Already Exist', HttpStatus.BAD_REQUEST);
    }
    //send otp via email
    await this.otpService.createOtpForVerification(data.email);
    return { message: 'otp sent to your email' };
  }

  async verifyOtp(data: VerifyOtpDto): Promise<any> {
    const user = await this.userService.findHasFullInfoUserByEmail(data.email);
    if (user) {
      throw new HttpException('User Already Exist', HttpStatus.BAD_REQUEST);
    }
    await this.otpService.verifyOtpCodeForVerification(data.email, data.code);
    //update isVerified method
    await this.userModel.create({ email: data.email, isVerified: true });
    return { message: 'otp verified successfully' };
  }
  async finishSignUp(data: FinishRegistrationDto): Promise<any> {
    // check if user is verified
    const verifiedUser = await this.userService.findVerifiedUserByEmail(
      data.email,
    );
    if (!verifiedUser) {
      throw new HttpException(
        'You are not verified User',
        HttpStatus.BAD_REQUEST,
      );
    }
    //check if the phone is unique
    const isPhoneExist = await this.userService.findUserByPhone(data.phone);
    if (isPhoneExist) {
      throw new HttpException('Phone Already Exist', HttpStatus.BAD_REQUEST);
    }
    //hash password
    const hashPassword = await hashedOtpOrPassword(data.password);
    const newUser = await this.userModel.findByIdAndUpdate(
      verifiedUser._id,
      {
        ...data,
        password: hashPassword,
        role: data.role ?? Role.User,
        hasFullInfo: true,
      },
      { new: true },
    );
    const token = this.jwtService.sign({
      id: newUser._id,
      role: newUser.role,
      permission: newUser.permissions,
    });
    return { user: newUser, token: token };
  }
  //===========================forgot password flow =================================//
  async forgotPassword(data: ForgotPasswordDto) {
    const user = await this.userService.findHasFullInfoUserByEmail(data.email);
    if (!user) {
      throw new HttpException('User Not Found', HttpStatus.NOT_FOUND);
    }
    //send otp via email
    await this.otpService.createOtpForForgotPassword(data.email);
    return { message: 'please check your emsil' };
  }

  async verifyOtpForForgotPassword(data: VerifyOtpForgotPasswordDto) {
    const user = await this.userService.findHasFullInfoUserByEmail(data.email);
    if (!user) {
      throw new HttpException('User Not Found', HttpStatus.NOT_FOUND);
    }
    await this.otpService.verifyOtpCodeForForgotPassword(data.email, data.code);
    return { message: 'otp verified successfully' };
  }
  //set new password
  async setNewPassword(data: SetNewPasswordDto) {
    const user = await this.userService.findUserForForgotPassword(data.email);
    if (!user) {
      throw new HttpException('User Not Found', HttpStatus.NOT_FOUND);
    }
    // hash password
    const hashedPassword = await hashedOtpOrPassword(data.password);
    await this.userModel.findByIdAndUpdate(
      user.id,
      {
        $set: { password: hashedPassword },
      },
      { new: true },
    );
    return { message: 'password changed successfully' };
  }
  //=============change password ===========//
  async changePassword(data: ChangePasswordDto, id: string) {
    const user = await this.userService.findUserById(id);
    if (!user) {
      throw new HttpException('User Not Found', HttpStatus.NOT_FOUND);
    }
    // check if password is correct
    const isPasswordMatched = await comparePassword(
      data.oldPassword,
      user.password,
    );
    if (!isPasswordMatched) {
      throw new HttpException(
        'old password not correct',
        HttpStatus.BAD_REQUEST,
      );
    }
    // hash password
    const hashedPassword = await hashedOtpOrPassword(data.newPassword);
    //check if the old and new password is the same
    const isPasswordSame = await comparePassword(
      data.newPassword,
      user.password,
    );
    if (isPasswordSame) {
      throw new HttpException(
        "old password and new password can't be same",
        HttpStatus.BAD_REQUEST,
      );
    }
    await this.userModel.findByIdAndUpdate(
      user.id,
      {
        $set: { password: hashedPassword },
      },
      { new: true },
    );
    return { message: 'password changed successfully' };
  }

  async sampleLogin(): Promise<any> {
    const user = await this.userService.findUserByEmail('tesfu9503@gmail.com');

    return { user: user };
  }
}
