import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { Broker } from 'src/brokers/schema/broker.schema';
import { Permissions } from 'src/utils/permissions.enum';
import { Role } from 'src/utils/role.enum';
export type UserDocument = HydratedDocument<User>;

@Schema({ timestamps: true })
export class User {
  @Prop({ type: mongoose.SchemaTypes.ObjectId, ref: 'Broker', default: null })
  broker: Broker;

  @Prop()
  firstName: string;

  @Prop()
  lastName: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ unique: true })
  phone: string;

  @Prop({ unique: true, select: false })
  password: string;

  @Prop({
    default:
      'https://t3.ftcdn.net/jpg/03/46/83/96/240_F_346839683_6nAPzbhpSkIpb8pmAwufkC7c5eD7wYws.jpg',
  })
  profile_image: string;

  @Prop({ default: false, select: false })
  isVerified: boolean;

  @Prop({ default: false, select: false })
  hasFullInfo: boolean;

  @Prop({ default: false })
  isAccountSuspended: boolean;

  @Prop({ default: Role.User })
  role: Role;

  @Prop({ default: [] })
  permissions: Permissions[];

  @Prop({ default: null })
  deviceId: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
