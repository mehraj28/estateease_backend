import { Module } from '@nestjs/common';
import { NotificationController } from './notification.controller';
import { NotificationService } from './notification.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Notification, NotificationSchema } from './schema/notification.schema';
import { OneSignalPushNotificationService } from 'src/services/push-notification.service';
import { MailService } from 'src/services/mail.service';
import { PaginationService } from 'src/services/pagination.service';
import { GlobalSettingsModule } from 'src/global-settings/global-settings.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Notification.name, schema: NotificationSchema },
    ]),
    GlobalSettingsModule,
  ],
  controllers: [NotificationController],
  providers: [
    NotificationService,
    OneSignalPushNotificationService,
    MailService,
    PaginationService,
  ],
  exports: [NotificationService],
})
export class NotificationModule {}
