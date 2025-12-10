import { Module } from '@nestjs/common';
import { PropertyTypeService } from './property-type.service';
import { PropertyTypeController } from './property-type.controller';
import { MongooseModule } from '@nestjs/mongoose';
import {
  PropertyType,
  PropertyTypeSchema,
} from './schema/property-type.schema';
import { PaginationService } from 'src/services/pagination.service';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: PropertyType.name, schema: PropertyTypeSchema },
    ]),
  ],
  providers: [PropertyTypeService, PaginationService],
  controllers: [PropertyTypeController],
})
export class PropertyTypeModule {}
