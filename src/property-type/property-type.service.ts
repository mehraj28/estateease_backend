import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { PropertyType } from './schema/property-type.schema';
import { PaginationService } from 'src/services/pagination.service';
import { Model } from 'mongoose';
import { CreatePropertyTypeDto } from './dto/create-propertyType.dto';

@Injectable()
export class PropertyTypeService {
  constructor(
    @InjectModel(PropertyType.name)
    private propertyTypeModel: Model<PropertyType>,
    private paginationService: PaginationService,
  ) {}

  //create property type
  async createPropertyType(
    createPropertyDto: CreatePropertyTypeDto,
  ): Promise<PropertyType> {
    const isNameExist = await this.propertyTypeModel.findOne({
      name: createPropertyDto.name.toLocaleLowerCase(),
    });
    if (isNameExist) {
      throw new HttpException(
        'property Type Already Exist',
        HttpStatus.CONFLICT,
      );
    }
    const propertyType = await this.propertyTypeModel.create({
      name: createPropertyDto.name.toLocaleLowerCase(), //make sure all are in lowercase
    });
    return propertyType;
  }

  //update
  async updatePropertyType(
    createPropertyDto: CreatePropertyTypeDto,
    id: string,
  ): Promise<PropertyType> {
    const propertyType = await this.propertyTypeModel.findById(id);
    if (!propertyType) {
      throw new HttpException(
        "property Type Doesn't Exist",
        HttpStatus.NOT_FOUND,
      );
    }
    const existingTypeWithSameName = await this.propertyTypeModel.findOne({
      _id: { $ne: id }, // Exclude the current type by its ID
      name: createPropertyDto.name.toLocaleLowerCase(),
    });

    if (existingTypeWithSameName) {
      throw new HttpException(
        'Property Type Name Already Exists',
        HttpStatus.CONFLICT,
      );
    }
    const updatedType = await this.propertyTypeModel.findByIdAndUpdate(
      id,
      { name: createPropertyDto.name },
      { new: true },
    );
    return updatedType;
  }

  // get single type
  async getSinglePropertyType(id: string): Promise<PropertyType> {
    const propertyType = await this.propertyTypeModel.findById(id);
    if (!propertyType) {
      throw new HttpException(
        "Property Type Doesn't Exist",
        HttpStatus.NOT_FOUND,
      );
    }

    return propertyType;
  }
  //delete type
  async deletePropertyType(id: string): Promise<string> {
    const propertyType = await this.propertyTypeModel.findByIdAndDelete(id);
    if (!propertyType) {
      throw new HttpException(
        "Property Type Doesn't Exist",
        HttpStatus.NOT_FOUND,
      );
    }
    return 'Property Type Deleted Successfully';
  }
  //get Property Type
  async getPropertyType(): Promise<PropertyType[]> {
    const propertyType = await this.propertyTypeModel.find();
    return propertyType;
  }
  //get all Property Types paginated
  async getAllPropertyTypes(page: number, perPage: number) {
    const allTypes = await this.propertyTypeModel.find();
    const totalPropertyTypes = allTypes.length;
    const paginatedData = this.paginationService.paginate(
      allTypes,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalPropertyTypes,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalPropertyTypes,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }

  //  //get Property Type for user
  async getPropertyTypeForUser(): Promise<PropertyType[]> {
    const propertyType = await this.propertyTypeModel.find();
    return propertyType;
  }
  //create property type bulk like array of string at a time buth check if exist or not
  async createPropertyTypeBulk(propertyType: { data: string[] }): Promise<any> {
    const data = propertyType.data;
    const propertyTypeArray = [];
    for (const type of data) {
      const isNameExist = await this.propertyTypeModel.findOne({
        name: type.toLocaleLowerCase(),
      });
      if (isNameExist) {
        throw new HttpException(
          `property Type ${isNameExist.name} Already Exist`,
          HttpStatus.CONFLICT,
        );
      }
      propertyTypeArray.push({ name: type.toLocaleLowerCase() });
    }
    const propertyTypeBulk = await this.propertyTypeModel.insertMany(
      propertyTypeArray,
    );
    return propertyTypeBulk;
  }
}
