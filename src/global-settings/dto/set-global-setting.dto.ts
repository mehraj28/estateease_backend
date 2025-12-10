import { IsNotEmpty, IsOptional, IsString } from 'class-validator';
export class GlobalSettingDto {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  bannedAdPrice: number;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  propertyAdPrice: number;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  propertyAdViewRange: number;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  appName: string;

  @IsNotEmpty()
  @IsString()
  dashboardUrl: string;
}
