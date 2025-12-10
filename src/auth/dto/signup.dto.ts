import {
  IsString,
  IsNotEmpty,
  IsEmail,
  IsEnum,
  IsOptional,
} from 'class-validator';
import { Permissions } from 'src/utils/permissions.enum';
import { Role } from 'src/utils/role.enum';
export class FinishSignUpDto {
  @IsNotEmpty()
  @IsString()
  firstName: string;

  @IsNotEmpty()
  @IsString()
  lastName: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'email is not valid' })
  email: string;

  @IsNotEmpty()
  @IsString()
  phone: string;

  @IsNotEmpty()
  @IsString()
  password: string;

  @IsOptional()
  @IsEnum(Role, { message: 'invalid role' })
  role: Role;

  @IsOptional()
  @IsEnum(Permissions, { message: 'invalid permission type' })
  permissions: Permissions;
}

export class FinishRegistrationDto {
  @IsNotEmpty()
  @IsString()
  firstName: string;

  @IsNotEmpty()
  @IsString()
  lastName: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'email is not valid' })
  email: string;

  @IsNotEmpty()
  @IsString()
  phone: string;

  @IsNotEmpty()
  @IsString()
  password: string;

  @IsOptional()
  @IsEnum(Role, { message: 'invalid role' })
  role: Role;

  @IsOptional()
  @IsEnum(Permissions, { message: 'invalid permission type' })
  permissions: Permissions;

  @IsNotEmpty()
  @IsString()
  deviceId: string;
}

export class SignUpDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'email is not valid' })
  email: string;
}

export class VerifyOtpDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'email is not valid' })
  email: string;

  @IsNotEmpty()
  @IsString()
  code: string;
}
