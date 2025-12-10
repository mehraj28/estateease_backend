import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Chat } from './schema/chat.schema';
import mongoose, { Model } from 'mongoose';
import { UsersService } from 'src/users/users.service';
import { isValidMongooseId } from 'src/helpers/id-validator';
import { PropertyService } from 'src/property/property.service';

@Injectable()
export class ChatService {
  constructor(
    @InjectModel(Chat.name) private chatModel: Model<Chat>,
    private usersService: UsersService,
    private propertyService: PropertyService,
  ) {}

  //find Single Chat
  async findChatByConversationId(id: string) {
    return await this.chatModel.findById(id);
  }
  //find chat by members id
  async findChatByMembersId(members: string[]) {
    const chat = await this.chatModel.findOne({
      members: { $all: members },
    });
    return chat;
  }
  //find chat this method may be used by other services
  async findChatById(id: string, sender: string, receiver: string) {
    const isConversationExist = await this.chatModel.findOne({
      _id: id,
      members: { $all: [sender, receiver] },
    });
    return isConversationExist;
  }
  // create conversation between users this method may be used by other services
  async createChat(users: string[]) {
    const userPromises = [];

    for (const userId of users) {
      userPromises.push(this.usersService.findUserById(userId));
    }

    const [user1, user2] = await Promise.all(userPromises);

    if (!user1 || !user2) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    //check if the users already have a conversation
    const isConversationExist = await this.chatModel.findOne({
      members: { $all: [users[0], users[1]] },
    });

    if (isConversationExist) {
      // throw new HttpException(
      //   'the users are already in conversation please provide the conversation id',
      //   HttpStatus.NOT_FOUND,
      // );
      return isConversationExist;
    }
    const chat = await this.chatModel.create({ members: users });
    return chat;
  }

  //get my conversations
  async getMyChats(userId: string) {
    if (!userId) {
      throw new HttpException('Invalid Id', HttpStatus.BAD_REQUEST);
    }
    if (!isValidMongooseId(userId)) {
      throw new HttpException('Invalid Id', HttpStatus.BAD_REQUEST);
    }
    // check if the userId is valid mongoose ID
    const isValidId = await isValidMongooseId(userId);
    if (!isValidId) {
      throw new HttpException('Invalid ID detected', HttpStatus.BAD_REQUEST);
    }

    const myChats = await this.chatModel.aggregate([
      {
        $match: {
          members: { $in: [new mongoose.Types.ObjectId(userId)] },
        },
      },
      {
        $lookup: {
          from: 'messages',
          localField: '_id',
          foreignField: 'conversation',
          as: 'messages',
        },
      },
      {
        $unwind: '$messages',
      },
      {
        $sort: {
          'messages.createdAt': 1,
        },
      },
      {
        $group: {
          _id: '$_id',
          members: { $first: '$members' },
          last_message: { $last: '$messages' },
          unread_count: {
            $sum: {
              $cond: {
                if: {
                  $and: [
                    { $eq: ['$messages.readAt', null] },
                    {
                      $ne: [
                        '$messages.sender',
                        new mongoose.Types.ObjectId(userId),
                      ],
                    },
                  ],
                },
                then: 1,
                else: 0,
              },
            },
          },
        },
      },
      {
        $sort: {
          'last_message.createdAt': -1,
        },
      },
      {
        $project: {
          members: 1,
          last_message: 1,
          unread_count: 1,
        },
      },
    ]);
    await this.usersService.populateUserInfo(myChats, 'members');
    await this.propertyService.populatePropertyInfo(
      myChats,
      'last_message.property',
    );

    //filter user before send chat to the user
    myChats.forEach((chat) => {
      chat.members = chat.members.filter((member: any) => member._id != userId);
    });
    return myChats;
  }
}
