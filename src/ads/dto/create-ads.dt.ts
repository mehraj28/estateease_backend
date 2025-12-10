import { IsString, IsNotEmpty, IsOptional, IsEnum } from 'class-validator';
import { PaymentMethod } from 'src/utils/payment-type.enum';
export class CreateAdsDto {
  @IsNotEmpty()
  @IsString()
  user: string;

  @IsNotEmpty()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsString()
  broker: string;

  @IsNotEmpty()
  @IsString()
  owner: string;

  @IsNotEmpty()
  @IsString()
  startDate: string;

  @IsNotEmpty()
  @IsString()
  endDate: string;

  @IsNotEmpty()
  @IsString()
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
  @IsEnum(PaymentMethod, { message: 'invalid payment method' })
  paymentMethod: PaymentMethod;
}

export class UpdateAdsDto {
  @IsOptional()
  @IsNotEmpty()
  @IsString()
  user: string;

  @IsOptional()
  @IsNotEmpty()
  @IsString()
  title: string;

  @IsOptional()
  @IsNotEmpty()
  @IsString()
  broker: string;

  @IsOptional()
  @IsNotEmpty()
  @IsString()
  owner: string;
  @IsOptional()
  @IsNotEmpty()
  @IsString()
  startDate: string;
  @IsOptional()
  @IsNotEmpty()
  @IsString()
  endDate: string;
  @IsOptional()
  @IsNotEmpty()
  @IsString()
  amount: string;
  @IsOptional()
  @IsNotEmpty()
  @IsString()
  paymentId: string;
  @IsOptional()
  @IsOptional()
  @IsString()
  description: string;
  @IsOptional()
  @IsNotEmpty()
  @IsOptional()
  @IsString()
  reason: string;
  @IsOptional()
  @IsNotEmpty()
  @IsString()
  email_address: string;
  @IsOptional()
  @IsNotEmpty()
  @IsString()
  currency: string;
  @IsOptional()
  @IsNotEmpty()
  @IsString()
  timestamp: string;
  @IsOptional()
  @IsNotEmpty()
  @IsEnum(PaymentMethod, { message: 'invalid payment method' })
  paymentMethod: PaymentMethod;
}

export class CreateAdsByAdminDto {
  @IsNotEmpty()
  @IsString()
  user: string;

  @IsNotEmpty()
  @IsString()
  title: string;

  // @IsNotEmpty()
  // @IsString()
  // owner: string;

  @IsNotEmpty()
  @IsString()
  startDate: string;

  @IsNotEmpty()
  @IsString()
  endDate: string;
}
