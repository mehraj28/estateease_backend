import {
  IsString,
  IsNotEmpty,
  IsEmail,
  IsEnum,
  IsOptional,
} from 'class-validator';
export class SendMessageDto {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  conversation: string;

  @IsNotEmpty()
  @IsString()
  sender: string;

  @IsNotEmpty()
  @IsString()
  receiver: string;

  @IsOptional()
  @IsString()
  message: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  property: string;
}
