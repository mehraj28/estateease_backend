import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsNumber,
  IsEnum,
} from 'class-validator';
import { PaymentMethod } from 'src/utils/payment-type.enum';
export class RequestFeaturedPropertyDto {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  property: string;

  @IsNotEmpty()
  @IsString()
  user: string;

  @IsNotEmpty()
  @IsNumber()
  viewCount: number;

  @IsNotEmpty()
  @IsNumber()
  amount: string;

  @IsNotEmpty()
  @IsString()
  paymentId: string;

  @IsOptional()
  @IsString()
  description: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  reason: string;

  @IsNotEmpty()
  @IsString()
  email_address: string;

  @IsNotEmpty()
  @IsString()
  currency: string;

  @IsNotEmpty()
  @IsString()
  timestamp: string;

  @IsNotEmpty()
  @IsString()
  broker: string;

  @IsNotEmpty()
  @IsEnum(PaymentMethod, { message: 'invalid payment method' })
  paymentMethod: PaymentMethod;
}
