import { Module, forwardRef } from '@nestjs/common';
import { PropertyController } from './property.controller';
import { PropertyService } from './property.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Property, PropertySchema } from './schema/property.schema';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { PaginationService } from 'src/services/pagination.service';
import { RatingModule } from 'src/rating/rating.module';
import {
  FeaturedProperty,
  FeaturedPropertySchema,
} from 'src/featured-property/schema/featured-property.schema';
import { FeaturedPropertyModule } from 'src/featured-property/featured-property.module';
import { AdsModule } from 'src/ads/ads.module';
import { BrokerPackagesModule } from 'src/broker-packages/broker-packages.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Property.name, schema: PropertySchema },
    ]),
    MongooseModule.forFeature([
      { name: FeaturedProperty.name, schema: FeaturedPropertySchema },
    ]),
    RatingModule,
    forwardRef(() => FeaturedPropertyModule),
    AdsModule,
    BrokerPackagesModule,
  ],
  exports: [
    MongooseModule.forFeature([
      { name: Property.name, schema: PropertySchema },
    ]),
    PropertyService,
  ],
  controllers: [PropertyController],
  providers: [PropertyService, CloudinaryService, PaginationService],
})
export class PropertyModule {}
