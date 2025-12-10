import { IsNotEmpty, IsEmail, IsString } from 'class-validator';
export class ForgotPasswordDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'email is not valid' })
  email: string;
}

export class VerifyOtpForgotPasswordDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'email is not valid' })
  email: string;

  @IsNotEmpty()
  @IsString()
  code: string;
}

export class SetNewPasswordDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'email is not valid' })
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;
}

export class ChangePasswordDto {
  @IsNotEmpty()
  @IsString()
  oldPassword: string;

  @IsNotEmpty()
  @IsString()
  newPassword: string;
}
