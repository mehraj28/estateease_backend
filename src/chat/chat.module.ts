import { Module } from '@nestjs/common';
import { ChatController } from './chat.controller';
import { ChatService } from './chat.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Chat, ChatSchema } from './schema/chat.schema';
import { UsersModule } from 'src/users/users.module';
import { PropertyModule } from 'src/property/property.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Chat.name, schema: ChatSchema }]),
    UsersModule,
    PropertyModule,
  ],
  controllers: [ChatController],
  providers: [ChatService],
  exports: [
    MongooseModule.forFeature([{ name: Chat.name, schema: ChatSchema }]),
    ChatService,
  ],
})
export class ChatModule {}
