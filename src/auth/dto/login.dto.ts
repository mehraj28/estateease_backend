import { IsString, IsNotEmpty, IsEmail } from 'class-validator';
export class LoginDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'email is not valid' })
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;

  @IsNotEmpty()
  @IsString()
  deviceId: string;
}

export class DashboardLoginDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'email is not valid' })
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;
}
