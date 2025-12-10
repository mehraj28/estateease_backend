import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Owner } from './schema/owner.schema';
import { Model } from 'mongoose';
import { CreateOwnerDto, UpdateOwnerDto } from './dto/create-owner.dto';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { PaginationService } from 'src/services/pagination.service';
@Injectable()
export class OwnerService {
  constructor(
    @InjectModel(Owner.name) private ownerModel: Model<Owner>,
    private readonly cloudinaryService: CloudinaryService,
    private readonly paginationService: PaginationService,
  ) {}

  async getOwnersCount() {
    return await this.ownerModel.countDocuments();
  }
  async createOwner(createOwnerDto: CreateOwnerDto, logo: Express.Multer.File) {
    //check if the real estate owner is already exist
    const existingOwner = await this.ownerModel.findOne({
      $or: [
        { name: createOwnerDto.name.trim() },
        { phone: createOwnerDto.phone },
        { email: createOwnerDto.email.trim() },
      ],
    });
    if (existingOwner) {
      if (existingOwner.name === createOwnerDto.name) {
        throw new HttpException('Name Already Exist', HttpStatus.CONFLICT);
      }

      if (existingOwner.phone === createOwnerDto.phone) {
        throw new HttpException('Phone Already Exist', HttpStatus.CONFLICT);
      }

      if (existingOwner.email === createOwnerDto.email) {
        throw new HttpException('Email Already Exist', HttpStatus.CONFLICT);
      }
    }
    const imageUrl = await this.cloudinaryService.uploadFile(logo);
    //create the owner
    const owner = await this.ownerModel.create({
      ...createOwnerDto,
      logo: imageUrl.secure_url,
    });
    return owner;
  }

  //update owner
  async updateOwner(
    id: string,
    updateOwnerDto: UpdateOwnerDto,
    logo?: Express.Multer.File,
  ) {
    // check if the owner is exist before updating it
    const isOwnerExist = await this.ownerModel.findById(id);
    if (!isOwnerExist) {
      throw new HttpException('Owner Does not Exist', HttpStatus.NOT_FOUND);
    }
    const existingOwner = await this.ownerModel.findOne({
      _id: { $ne: isOwnerExist?._id }, // Exclude the current owner from the search
      $or: [
        { name: updateOwnerDto.name.trim() },
        { phone: updateOwnerDto.phone },
        { email: updateOwnerDto.email.trim() },
      ],
    });

    if (existingOwner) {
      if (existingOwner.name === updateOwnerDto.name) {
        throw new HttpException('Name Already Exist', HttpStatus.CONFLICT);
      }

      if (existingOwner.phone === updateOwnerDto.phone) {
        throw new HttpException('Phone Already Exist', HttpStatus.CONFLICT);
      }

      if (existingOwner.email === updateOwnerDto.email) {
        throw new HttpException('Email Already Exist', HttpStatus.CONFLICT);
      }
    }

    // check if the logo is exist
    if (logo) {
      const imageUrl = await this.cloudinaryService.uploadFile(logo);
      const updateOwner = await this.ownerModel.findByIdAndUpdate(
        id,
        {
          $set: { ...updateOwnerDto, logo: imageUrl.secure_url },
        },
        { new: true },
      );
      return updateOwner;
    } else {
      const updateOwner = await this.ownerModel.findByIdAndUpdate(
        id,
        {
          $set: { ...updateOwnerDto },
        },
        { new: true },
      );
      return updateOwner;
    }
  }

  //get all owner for use while creating property for admin broker or agent
  async getAllOwners() {
    return await this.ownerModel.find();
  }

  //get owner by admin or its agents
  async getAllOwnerForAdmin(page: number, perPage: number) {
    const allOwners = await this.ownerModel.find();
    const totalOwners = allOwners.length;
    const paginatedData = this.paginationService.paginate(
      allOwners,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalOwners,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalOwners,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }

  //*-----------------------starting from this line the apis are for the user application section-------------------*
  async getAllOwnersForUser() {
    const owners = await this.ownerModel.find();
    return owners;
  }
}
