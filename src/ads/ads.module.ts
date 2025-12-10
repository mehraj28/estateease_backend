import { Module } from '@nestjs/common';
import { AdsController } from './ads.controller';
import { AdsService } from './ads.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Ads, AdsSchema } from './schema/ad.schema';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { PaymentModule } from 'src/payment/payment.module';
import { PaginationService } from 'src/services/pagination.service';
import { NotificationModule } from 'src/notification/notification.module';
import { UsersModule } from 'src/users/users.module';
import { SendAdsNotificationAndEmailInterceptor } from 'src/interceptors/notification.interceptors';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Ads.name, schema: AdsSchema }]),
    PaymentModule,
    NotificationModule,
    UsersModule,
  ],
  controllers: [AdsController],
  providers: [
    AdsService,
    CloudinaryService,
    PaginationService,
    SendAdsNotificationAndEmailInterceptor,
  ],
  exports: [
    MongooseModule.forFeature([{ name: Ads.name, schema: AdsSchema }]),
    AdsService,
  ],
})
export class AdsModule {}
