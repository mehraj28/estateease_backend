import { IsString, IsNotEmpty } from 'class-validator';
export class IdDto {
  @IsNotEmpty()
  @IsString()
  id: string;
}
