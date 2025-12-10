import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { Ads } from 'src/ads/schema/ad.schema';
import { BrokerPackage } from 'src/broker-packages/schema/broker-package.schema';
import { BrokerRequest } from 'src/broker-request/schema/broker-request-schema';
import { FeaturedProperty } from 'src/featured-property/schema/featured-property.schema';
import { Payment } from 'src/payment/schema/payment.schema';
import { Property } from 'src/property/schema/property.schema';
import { Report } from 'src/report/schema/report.schema';
import { User } from 'src/users/schema/user.schema';
import {
  NotificationSender,
  NotificationPriority,
} from 'src/utils/notifications.enum';

export type NotificationDocument = HydratedDocument<Notification>;

@Schema({ timestamps: true })
export class Notification {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null,
  })
  user: User;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Payment',
    default: null,
  })
  payment: Payment;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Property',
    default: null,
  })
  property: Property;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'FeaturedProperty',
    default: null,
  })
  featuredProperty: FeaturedProperty;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Ads',
    default: null,
  })
  ads: Ads;

  //broker request

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'BrokerRequest',
    default: null,
  })
  broker_request: BrokerRequest;

  //brokers package
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'BrokerPackage',
    default: null,
  })
  broker_package: BrokerPackage;

  //property report
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Report',
    default: null,
  })
  report: Report;
  @Prop({ required: true })
  title: string;

  @Prop({ required: true })
  body: string;

  @Prop({ default: null })
  readAt: Date;

  @Prop([
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
  ])
  recipients: User[];

  @Prop({ enum: NotificationSender, default: NotificationSender.SYSTEM })
  sender: NotificationSender;

  @Prop({ enum: NotificationPriority, default: NotificationPriority.NORMAL })
  priority: NotificationPriority;
}

export const NotificationSchema = SchemaFactory.createForClass(Notification);
