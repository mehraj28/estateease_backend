import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsNumber,
  IsArray,
  ValidateNested,
} from 'class-validator';
import { PropertyTypes } from 'src/utils/property.enum';

class PropertyDetail {
  @IsNotEmpty()
  @IsNumber()
  area: number;

  @IsNotEmpty()
  @IsNumber()
  bathroom: number;

  @IsNotEmpty()
  @IsNumber()
  bedroom: number;

  @IsNotEmpty()
  @IsNumber()
  yearBuilt: number;

  @IsNotEmpty()
  @IsNumber()
  @IsOptional()
  floor: number;
}

class PropertyFacilities {
  @IsNotEmpty()
  @IsString()
  facility: string;

  @IsNotEmpty()
  @IsNumber()
  distance: number;
}
class Address {
  @IsNotEmpty()
  @IsString()
  city: string;

  @IsNotEmpty()
  @IsString()
  location: string;

  @IsNotEmpty()
  @IsArray()
  loc: Array<number>;
}
export class CreatePropertyDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  poster: string;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  broker: string;

  @IsNotEmpty()
  @IsString()
  price: string;

  @IsNotEmpty()
  @IsString()
  currency: string;

  @IsNotEmpty()
  @IsString()
  description: string;

  @IsNotEmpty()
  @IsString()
  paymentDescription: string;

  @IsNotEmpty()
  @IsString()
  propertyType: string;

  @IsNotEmpty()
  @IsString()
  propertyHomeType: string;

  @IsNotEmpty()
  @IsString()
  owner: string;

  @IsNotEmpty()
  @IsString()
  agent: string;

  @ValidateNested()
  details: PropertyDetail;

  @ValidateNested()
  address: Address;

  @ValidateNested()
  @IsOptional()
  facilities: PropertyFacilities;

  @IsNotEmpty()
  @IsArray()
  amenities: Array<string>;
}
export class UpdatePropertyDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  poster: string;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  broker: string;

  @IsNotEmpty()
  @IsString()
  price: string;

  @IsNotEmpty()
  @IsString()
  currency: string;

  @IsNotEmpty()
  @IsString()
  description: string;

  // @IsNotEmpty()
  // @IsArray()
  // images: { _id: string; url: string }[];

  @IsNotEmpty()
  @IsString()
  paymentDescription: string;

  @IsNotEmpty()
  @IsString()
  propertyType: string;

  @IsNotEmpty()
  @IsString()
  propertyHomeType: string;

  @IsNotEmpty()
  @IsString()
  owner: string;

  @IsNotEmpty()
  @IsString()
  agent: string;

  @ValidateNested()
  details: PropertyDetail;

  @ValidateNested()
  address: Address;

  @ValidateNested()
  @IsOptional()
  facilities: PropertyFacilities;

  @IsNotEmpty()
  @IsArray()
  amenities: Array<string>;
}

export class FilterPropertyDto {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  propertyType: PropertyTypes;

  @IsOptional()
  @IsNotEmpty()
  @IsString()
  propertyHomeType: string;

  @IsOptional()
  @IsNotEmpty()
  @IsString()
  owner: string;

  @IsOptional()
  @IsNotEmpty()
  @IsNumber()
  maxPrice: number;

  @IsOptional()
  @IsNotEmpty()
  @IsNumber()
  minPrice: number;

  @IsOptional()
  @IsNotEmpty()
  @IsNumber()
  bathroom: number;

  @IsOptional()
  @IsNotEmpty()
  @IsNumber()
  bedroom: number;

  @IsOptional()
  @IsNotEmpty()
  @IsNumber()
  area: number;

  @IsOptional()
  @IsNotEmpty()
  @IsNumber()
  page: number;

  @IsOptional()
  @IsNotEmpty()
  @IsNumber()
  perPage: number;
}

export class DeletePropertyImageDto {
  @IsNotEmpty()
  @IsString()
  id: string;

  @IsNotEmpty()
  @IsString()
  imageId: string;
}
