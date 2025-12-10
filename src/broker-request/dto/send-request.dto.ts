import { IsString, IsNotEmpty, IsOptional, IsNumber } from 'class-validator';
export class SendRequestDto {
  @IsNotEmpty()
  @IsString()
  user: string;

  @IsNotEmpty()
  @IsString()
  companyName: string;

  @IsNotEmpty()
  @IsString()
  address: string;

  @IsNotEmpty()
  @IsString()
  phone: string;

  @IsOptional()
  email: string;
}

export class AcceptRequestDto {
  @IsOptional()
  @IsNotEmpty()
  @IsNumber()
  freeListingQuota: number;

  @IsOptional()
  @IsNotEmpty()
  @IsNumber()
  freeListingQuotaRemaining: number;
}

export class RejectRequestDto {
  @IsOptional()
  @IsNotEmpty()
  @IsString()
  message: string;
}
