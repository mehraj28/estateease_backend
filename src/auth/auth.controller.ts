import { Body, Controller, Post, Put, Param, Get, Query } from '@nestjs/common';
import { AuthService } from './auth.service';
import { DashboardLoginDto, LoginDto } from './dto/login.dto';
import {
  FinishRegistrationDto,
  SignUpDto,
  VerifyOtpDto,
} from './dto/signup.dto';
import {
  ForgotPasswordDto,
  VerifyOtpForgotPasswordDto,
  SetNewPasswordDto,
  ChangePasswordDto,
} from './dto/forgot-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/dashboard/login')
  async DashboardLogin(@Body() loginDto: DashboardLoginDto): Promise<any> {
    return await this.authService.dashboardLogin(loginDto);
  }

  @Post('/login')
  async userLogin(@Body() loginDto: LoginDto): Promise<any> {
    return await this.authService.userLogin(loginDto);
  }

  @Get('/create-admin')
  async initializeAdminAccount(@Query('email') email: string): Promise<any> {
    return await this.authService.createIntialAdminAccount(email);
  }

  @Post('/create-admin')
  async createAdminAccount(
    @Body() signUpDto: FinishRegistrationDto,
  ): Promise<any> {
    return await this.authService.createAdminAccount(signUpDto);
  }
  //================sign up flow ===============//

  @Post('/signup')
  async signUp(@Body() signUpDto: SignUpDto): Promise<any> {
    return await this.authService.signUp(signUpDto);
  }

  @Post('/verify-otp')
  async verifyOtp(@Body() verifyOtpDto: VerifyOtpDto): Promise<any> {
    return await this.authService.verifyOtp(verifyOtpDto);
  }

  @Put('/finish-signup')
  async finishSignUp(
    @Body() finishSignUpDto: FinishRegistrationDto,
  ): Promise<any> {
    return await this.authService.finishSignUp(finishSignUpDto);
  }

  //================forgot password flow ===============//
  @Post('/forgot-password')
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
  ): Promise<any> {
    return await this.authService.forgotPassword(forgotPasswordDto);
  }
  //verify otp
  @Post('/forgot-password/verify-otp')
  async verifyOtpForForgotPassword(
    @Body() verifyOtpForgotPasswordDto: VerifyOtpForgotPasswordDto,
  ): Promise<any> {
    return await this.authService.verifyOtpForForgotPassword(
      verifyOtpForgotPasswordDto,
    );
  }

  @Put('/forgot-password/set-new-password')
  async setNewPassword(
    @Body() setNewPasswordDto: SetNewPasswordDto,
  ): Promise<any> {
    return await this.authService.setNewPassword(setNewPasswordDto);
  }
  //==================change password ===============//
  @Put('/change-password/:id')
  async changePassword(
    @Param('id') id: string,
    @Body() changePasswordDto: ChangePasswordDto,
  ): Promise<any> {
    return await this.authService.changePassword(changePasswordDto, id);
  }
  @Post('/sample-login')
  async sampleLogin(@Body() data: any): Promise<any> {
    return await this.authService.sampleLogin();
  }
}
