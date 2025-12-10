import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Package } from './schema/package.schema';
import { Model } from 'mongoose';
import { CreatePackageDto } from './dto/create-package.dto';

@Injectable()
export class PackagesService {
  constructor(
    @InjectModel(Package.name) private packageModel: Model<Package>,
  ) {}

  ///*************Method usd by other services */
  // get package by id
  async getPackageById(packageId: string) {
    const packageFound = await this.packageModel.findById(packageId);
    if (!packageFound) {
      throw new HttpException('Package Not Found', HttpStatus.NOT_FOUND);
    }
    return packageFound;
  }

  //create package by admin
  async createNewPackage(createPackageDto: CreatePackageDto) {
    const isNameExist = await this.packageModel.findOne({
      name: createPackageDto.name,
    });
    if (isNameExist) {
      throw new HttpException(
        'Package Name Already Exist',
        HttpStatus.CONFLICT,
      );
    }
    const newPackage = await this.packageModel.create(createPackageDto);
    return newPackage;
  }

  //update package
  async updatePackage(createPackageDto: CreatePackageDto, id: string) {
    const packageExist = await this.packageModel.findById(id);
    if (!packageExist) {
      throw new HttpException(
        'Package Does Not Exist Exist',
        HttpStatus.NOT_FOUND,
      );
    }
    const updatePackage = await this.packageModel.findByIdAndUpdate(
      id,
      { $set: { ...createPackageDto } },
      { new: true },
    );
    return updatePackage;
  }

  //delelte package
  async deletePackage(id: string) {
    const packageExist = await this.packageModel.findById(id);
    if (!packageExist) {
      throw new HttpException('Package Does Not Exist', HttpStatus.NOT_FOUND);
    }
    await this.packageModel.findByIdAndDelete(id);
    return 'Package Deleted Successfully';
  }
  // get all packages for admin or  brokers
  async getAllPackages() {
    return await this.packageModel.find({});
  }
}
