import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { User } from 'src/users/schema/user.schema';
import { BrokerRequestStatus } from 'src/utils/status.enum';

export type BrokerRequestDocument = HydratedDocument<BrokerRequest>;

@Schema({ timestamps: true })
export class BrokerRequest {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  user: User;

  @Prop()
  companyName: string;

  @Prop()
  logo: string;

  @Prop()
  coverImage: string;

  @Prop()
  document: string;

  @Prop()
  address: string;

  @Prop({ unique: true })
  phone: string;

  @Prop({ unique: true })
  email: string;

  @Prop({ default: false })
  isApproved: boolean;

  @Prop({ default: false })
  isRejected: boolean;

  @Prop({ default: BrokerRequestStatus.PENDING })
  status: BrokerRequestStatus;
}

export const BrokerRequestSchema = SchemaFactory.createForClass(BrokerRequest);
