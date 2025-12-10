import { Module, forwardRef } from '@nestjs/common';
import { FeaturedPropertyController } from './featured-property.controller';
import { FeaturedPropertyService } from './featured-property.service';
import { MongooseModule } from '@nestjs/mongoose';
import {
  FeaturedProperty,
  FeaturedPropertySchema,
} from './schema/featured-property.schema';
import { PropertyModule } from 'src/property/property.module';
import { PaymentModule } from 'src/payment/payment.module';
import { PaginationService } from 'src/services/pagination.service';
import { UpdateViewCountInterceptor } from 'src/interceptors/property.interceptors';
import { SendFeaturePropertyNotificationAndEmailInterceptor } from 'src/interceptors/notification.interceptors';
import { UsersModule } from 'src/users/users.module';
import { NotificationModule } from 'src/notification/notification.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: FeaturedProperty.name, schema: FeaturedPropertySchema },
    ]),
    PaymentModule,
    UsersModule,
    NotificationModule,
    forwardRef(() => PropertyModule),
  ],
  controllers: [FeaturedPropertyController],
  providers: [
    FeaturedPropertyService,
    PaginationService,
    UpdateViewCountInterceptor,
    SendFeaturePropertyNotificationAndEmailInterceptor,
  ],
  exports: [FeaturedPropertyService],
})
export class FeaturedPropertyModule {}
