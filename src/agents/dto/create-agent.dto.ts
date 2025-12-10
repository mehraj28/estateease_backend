import {
  IsString,
  IsNotEmpty,
  IsEmail,
  IsEnum,
  IsOptional,
} from 'class-validator';
import { Permissions } from 'src/utils/permissions.enum';
import { Role } from 'src/utils/role.enum';
export class CreateAgentDto {
  @IsOptional()
  @IsNotEmpty()
  @IsString()
  broker: string;

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
  @IsNotEmpty()
  @IsString()
  whatsappNumber: string;

  @IsNotEmpty()
  @IsEnum(Role, { message: 'invalid role' })
  role: Role;

  @IsOptional()
  @IsEnum(Permissions, { message: 'invalid permission type' })
  permissions: Permissions;
}
