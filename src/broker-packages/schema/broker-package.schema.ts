import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { Broker } from 'src/brokers/schema/broker.schema';
import { Package } from 'src/packages/schema/package.schema';
import { Payment } from 'src/payment/schema/payment.schema';
import { User } from 'src/users/schema/user.schema';
import { ListingQuotaStatus } from 'src/utils/status.enum';

export type BrokerPackageDocument = HydratedDocument<BrokerPackage>;

@Schema({ timestamps: true })
export class BrokerPackage {
  @Prop({ type: Package, required: true, unique: false })
  package: Package;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Broker', required: true })
  broker: Broker;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Payment',
    required: true,
  })
  payment: Payment;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  user: User;

  @Prop({ default: false })
  isActive: boolean;

  @Prop({ default: ListingQuotaStatus.PENDING })
  status: ListingQuotaStatus;
}

export const BrokerPackageSchema = SchemaFactory.createForClass(BrokerPackage);
