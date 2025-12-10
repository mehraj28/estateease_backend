import { Module } from '@nestjs/common';
import { MessagesController } from './messages.controller';
import { MessagesService } from './messages.service';
import { ChatService } from 'src/chat/chat.service';
import { Message, MessageSchema } from './schema/message.schema';
import { UsersModule } from 'src/users/users.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ChatModule } from 'src/chat/chat.module';
import { PropertyModule } from 'src/property/property.module';
import { OneSignalPushNotificationService } from 'src/services/push-notification.service';
import { GlobalSettingsModule } from 'src/global-settings/global-settings.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Message.name, schema: MessageSchema }]),
    UsersModule,
    ChatModule,
    PropertyModule,
    GlobalSettingsModule,
  ],
  controllers: [MessagesController],
  providers: [MessagesService, ChatService, OneSignalPushNotificationService],
})
export class MessagesModule {}
