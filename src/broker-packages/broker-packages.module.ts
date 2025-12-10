import { Module } from '@nestjs/common';
import { BrokerPackagesController } from './broker-packages.controller';
import { BrokerPackagesService } from './broker-packages.service';
import { MongooseModule } from '@nestjs/mongoose';
import {
  BrokerPackage,
  BrokerPackageSchema,
} from './schema/broker-package.schema';
import { PaymentModule } from 'src/payment/payment.module';
import { PackagesModule } from 'src/packages/packages.module';
import { PaginationService } from 'src/services/pagination.service';
import { UsersModule } from 'src/users/users.module';
import { NotificationModule } from 'src/notification/notification.module';
import { SendListingPackageNotificationAndEmailInterceptor } from 'src/interceptors/notification.interceptors';
import { BrokersModule } from 'src/brokers/brokers.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: BrokerPackage.name, schema: BrokerPackageSchema },
    ]),
    PackagesModule,
    PaymentModule,
    UsersModule,
    NotificationModule,
    BrokersModule,
  ],
  controllers: [BrokerPackagesController],
  providers: [
    BrokerPackagesService,
    PaginationService,
    SendListingPackageNotificationAndEmailInterceptor,
  ],
  exports: [BrokerPackagesService],
})
export class BrokerPackagesModule {}
