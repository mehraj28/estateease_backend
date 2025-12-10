import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { Chat } from 'src/chat/schema/chat.schema';
import { Property } from 'src/property/schema/property.schema';
import { User } from 'src/users/schema/user.schema';

export type messageDocument = HydratedDocument<Message>;

@Schema({ timestamps: true })
export class Message {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Message' })
  conversation: Chat;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Property',
    default: null,
  })
  property: Property;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  sender: User;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  receiver: User;

  @Prop({ default: null })
  readAt: Date;

  @Prop({ default: null })
  message: string;
}

export const MessageSchema = SchemaFactory.createForClass(Message);
