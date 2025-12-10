import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { Broker } from 'src/brokers/schema/broker.schema';
import { Package } from 'src/packages/schema/package.schema';
import { User } from 'src/users/schema/user.schema';
import { PaymentMethod } from 'src/utils/payment-type.enum';
import { PaymentStatus } from 'src/utils/status.enum';

export type PaymentDocument = HydratedDocument<Payment>;

@Schema({ timestamps: true })
export class Payment {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Package', default: null })
  package: Package;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  user: User;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Broker' })
  broker: Broker;

  @Prop({ required: true })
  amount: string;

  @Prop({ required: true })
  email_address: string;

  @Prop({ required: true })
  description: string;

  @Prop({ required: true })
  currency: string;

  @Prop()
  reason: string;

  @Prop({ required: true })
  paymentMethod: PaymentMethod;

  @Prop({ required: true })
  paymentId: string;

  @Prop({ required: true })
  timestamp: Date;

  @Prop({ default: PaymentStatus.PENDING })
  status: PaymentStatus;
}

export const PaymentSchema = SchemaFactory.createForClass(Payment);
