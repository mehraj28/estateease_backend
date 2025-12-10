import { IsString, IsNotEmpty, IsEmail, IsOptional } from 'class-validator';

export class UpdateProfileDto {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  firstName: string;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  lastName: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'email is not valid' })
  @IsOptional()
  email: string;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  phone: string;
}
