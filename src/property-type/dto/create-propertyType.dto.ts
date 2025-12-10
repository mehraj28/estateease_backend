import { IsString, IsNotEmpty } from 'class-validator';
export class CreatePropertyTypeDto {
  @IsNotEmpty()
  @IsString()
  name: string;
}
