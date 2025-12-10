import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Message } from './schema/message.schema';
import { Model } from 'mongoose';
import { SendMessageDto } from './dto/send-message.dto';
import { ChatService } from 'src/chat/chat.service';
import { isValidMongooseId } from 'src/helpers/id-validator';
import { OneSignalPushNotificationService } from 'src/services/push-notification.service';
import { GlobalSettingsService } from 'src/global-settings/global-settings.service';

@Injectable()
export class MessagesService {
  constructor(
    @InjectModel(Message.name) private messageModel: Model<Message>,
    private chatService: ChatService,
    private readonly pushNotificationService: OneSignalPushNotificationService,
    private readonly globalSettingsService: GlobalSettingsService,
  ) {}

  //send message but if there is no chat(conversation) between users, create one
  async sendMessage(data: SendMessageDto) {
    const setting = await this.globalSettingsService.getGlobalSettings();
    if (data.property) {
      const [id1, id2, id3] = await Promise.all([
        isValidMongooseId(data.sender),
        isValidMongooseId(data.receiver),
        isValidMongooseId(data.property),
      ]);

      if (!id1 || !id2 || !id3) {
        throw new HttpException('Invalid ID detected', HttpStatus.NOT_FOUND);
      }
    } else {
      const [id1, id2] = await Promise.all([
        isValidMongooseId(data.sender),
        isValidMongooseId(data.receiver),
      ]);

      if (!id1 || !id2) {
        throw new HttpException('Invalid ID detected', HttpStatus.NOT_FOUND);
      }
    }
    // Check if message or property field is missing
    if (!data.property && !data.message) {
      throw new HttpException(
        'message or property field is required',
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    let chatId: any;

    // Find the conversation if conversation ID is provided
    if (data.conversation) {
      const isChatExist = await this.chatService.findChatById(
        data.conversation,
        data.sender,
        data.receiver,
      );
      if (isChatExist) {
        chatId = isChatExist._id;
      }
    } else {
      // If no conversation ID is provided, create a new chat
      const createChat = await this.chatService.createChat([
        data.sender,
        data.receiver,
      ]);

      if (createChat) {
        chatId = createChat._id;
      }
    }

    if (chatId) {
      console.log(chatId);
      // Create and send the message
      const newMessage = await this.messageModel.create({
        conversation: chatId,
        ...data,
      });

      await this.pushNotificationService.pushNotificationToSingleUser({
        message: `${data.message}`,
        deviceId: '2b75365c-9a88-4be7-b810-9a8989b653c9',
        appIcon: setting.appLogo,
      });
      return newMessage;
    } else {
      throw new HttpException('Chat not found', HttpStatus.NOT_FOUND);
    }
  }

  //get message of a chat senderId recieverId
  async getAllMessages(id: string[]) {
    if (!id[0] || !id[1]) {
      throw new HttpException(
        'please provide sender and receiver id',
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }
    const isChatExist = await this.chatService.findChatByMembersId(id);
    if (!isChatExist) {
      throw new HttpException(
        'you guys are not in conversation',
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }
    //find all messages by users id
    const messages = await this.messageModel
      .find({ conversation: isChatExist._id })
      .sort({
        createdAt: -1,
      })
      .populate('property')
      .populate('sender')
      .populate('receiver');

    if ((messages[0].receiver as any)?._id?.toString() === id[0]) {
      console.log('updated');
      await this.messageModel.updateMany(
        { conversation: isChatExist._id, readAt: null },
        { readAt: new Date() },
        { new: true },
      );
    }
    return messages;
  }
  //get all messages of a user
  async getAllUserMessages(id: string) {
    const allMessages = await this.messageModel
      .find({
        $or: [{ sender: id }, { receiver: id }],
      })
      .sort({
        createdAt: -1,
      })
      .populate('property')
      .populate('sender')
      .populate('receiver');
    return allMessages;
  }
}
