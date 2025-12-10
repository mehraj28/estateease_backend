import { IsString, IsNotEmpty } from 'class-validator';
export class ReportPropertyDto {
  @IsNotEmpty()
  @IsString()
  user: string;

  @IsNotEmpty()
  @IsString()
  discription: string;

  @IsNotEmpty()
  @IsString()
  property: string;
}

export class HideReportPropertyDto {
  @IsNotEmpty()
  @IsString()
  message: string;
}
