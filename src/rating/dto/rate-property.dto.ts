import { IsString, IsNotEmpty, IsNumber } from 'class-validator';
export class RatePropertyDto {
  @IsNotEmpty()
  @IsString()
  user: string;

  @IsNotEmpty()
  @IsString()
  property: string;

  @IsNotEmpty()
  @IsString()
  review: string;

  @IsNotEmpty()
  @IsNumber()
  rate: number;
}
