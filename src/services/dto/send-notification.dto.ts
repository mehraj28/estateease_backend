import { IsString, IsNotEmpty, IsOptional } from 'class-validator';
export class SendNotificationDto {
  @IsNotEmpty()
  @IsString()
  deviceId: string;

  @IsNotEmpty()
  @IsString()
  message: string;

  @IsNotEmpty()
  @IsString()
  appIcon: string;
}

export class SendNotificationToAllDto {
  @IsNotEmpty()
  @IsString()
  message: string;

  @IsNotEmpty()
  @IsString()
  appIcon: string;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  bigPicture: string;
}
