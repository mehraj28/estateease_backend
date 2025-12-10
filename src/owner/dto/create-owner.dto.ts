import { IsString, IsNotEmpty, IsOptional, IsNumber } from 'class-validator';
export class CreateOwnerDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  address: string;

  @IsNotEmpty()
  @IsString()
  phone: string;

  @IsOptional()
  email: string;
}

export class UpdateOwnerDto {
  @IsString()
  @IsOptional()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsOptional()
  @IsNotEmpty()
  address: string;

  @IsString()
  @IsOptional()
  @IsNotEmpty()
  phone: string;

  @IsString()
  @IsOptional()
  @IsNotEmpty()
  email: string;
}
