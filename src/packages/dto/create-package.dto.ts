import { IsString, IsNotEmpty, IsNumber } from 'class-validator';
export class CreatePackageDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  description: string;

  @IsNotEmpty()
  @IsNumber()
  maxListingsAllowed: number;

  @IsNotEmpty()
  @IsNumber()
  remining: number;

  @IsNotEmpty()
  @IsNumber()
  price: number;
}
