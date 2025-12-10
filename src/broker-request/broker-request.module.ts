import { Module } from '@nestjs/common';
import { BrokerRequestController } from './broker-request.controller';
import { BrokerRequestService } from './broker-request.service';
import { MongooseModule } from '@nestjs/mongoose';
import {
  BrokerRequest,
  BrokerRequestSchema,
} from './schema/broker-request-schema';
import { UsersModule } from 'src/users/users.module';
import { CloudinaryModule } from 'src/cloudinary/cloudinary.module';
import { PaginationService } from 'src/services/pagination.service';
import { BrokersModule } from 'src/brokers/brokers.module';
import { AgentsModule } from 'src/agents/agents.module';
import { NotificationModule } from 'src/notification/notification.module';
import { SendBrokerRequestNotificationAndEmailInterceptor } from 'src/interceptors/notification.interceptors';
import { MailService } from 'src/services/mail.service';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: BrokerRequest.name, schema: BrokerRequestSchema },
    ]),
    UsersModule,
    CloudinaryModule,
    BrokersModule,
    AgentsModule,
    UsersModule,
    NotificationModule,
  ],
  controllers: [BrokerRequestController],
  providers: [
    BrokerRequestService,
    PaginationService,
    SendBrokerRequestNotificationAndEmailInterceptor,
    MailService,
  ],
})
export class BrokerRequestModule {}
