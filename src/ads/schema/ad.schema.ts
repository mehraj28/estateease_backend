import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { Broker } from 'src/brokers/schema/broker.schema';
import { Owner } from 'src/owner/schema/owner.schema';
import { Payment } from 'src/payment/schema/payment.schema';
import { AdsBannerStatus } from 'src/utils/status.enum';

export type AdsDocument = HydratedDocument<Ads>;

@Schema({ timestamps: true })
export class Ads {
  @Prop()
  title: string;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Broker', default: null })
  broker: Broker;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Owner', default: null })
  owner: Owner;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Payment' })
  payment: Payment;

  @Prop({ required: true })
  image: string;

  @Prop({ required: true })
  startDate: Date;

  @Prop({ required: true })
  endDate: Date;

  @Prop({ default: false })
  isEdited: boolean;

  @Prop({ default: false })
  isApproved: boolean;

  @Prop({ default: false })
  isRejected: boolean;

  @Prop({ default: false })
  isDeleted: boolean;

  @Prop({ default: false })
  isInHouseAd: boolean;

  @Prop({ default: AdsBannerStatus.PENDING })
  status: AdsBannerStatus;
}

export const AdsSchema = SchemaFactory.createForClass(Ads);
