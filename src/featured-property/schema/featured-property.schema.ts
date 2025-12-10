import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { Broker } from 'src/brokers/schema/broker.schema';
import { Payment } from 'src/payment/schema/payment.schema';
import { Property } from 'src/property/schema/property.schema';
import { User } from 'src/users/schema/user.schema';
import { FeaturedPropertyStatus } from 'src/utils/status.enum';

export type FeaturedPropertyDocument = HydratedDocument<FeaturedProperty>;

@Schema({ timestamps: true })
export class FeaturedProperty {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  })
  user: User;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Broker',
    required: true,
  })
  broker: Broker;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Property',
    required: true,
  })
  property: Property;

  @Prop([
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Payment',
      required: true,
    },
  ])
  payment: Payment[];

  @Prop()
  viewCount: number;

  //number of views got by user
  @Prop({ default: 0 })
  numberOfViews: number;

  @Prop({ default: false })
  isRequestUpdate: boolean;

  //is the ads view count is ended
  @Prop({ default: false })
  isEnded: boolean;

  @Prop({ default: FeaturedPropertyStatus.PENDING })
  status: FeaturedPropertyStatus;
}

export const FeaturedPropertySchema =
  SchemaFactory.createForClass(FeaturedProperty);
