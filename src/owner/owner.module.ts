import { Module } from '@nestjs/common';
import { OwnerController } from './owner.controller';
import { OwnerService } from './owner.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Owner, OwnerSchema } from './schema/owner.schema';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { AuthModule } from 'src/auth/auth.module';
import { PaginationService } from 'src/services/pagination.service';
@Module({
  imports: [
    MongooseModule.forFeature([{ name: Owner.name, schema: OwnerSchema }]),
    AuthModule,
  ],
  exports: [
    MongooseModule.forFeature([{ name: Owner.name, schema: OwnerSchema }]),
    OwnerService,
  ],
  controllers: [OwnerController],
  providers: [OwnerService, CloudinaryService, PaginationService],
})
export class OwnerModule {}
