import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { Package } from 'src/packages/schema/package.schema';

export type BrokerDocument = HydratedDocument<Broker>;

@Schema({ timestamps: true })
export class Broker {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Package' })
  listingPackage: Package;

  @Prop({ unique: true, required: true })
  name: string;

  @Prop()
  logo: string;

  @Prop({ default: null })
  coverImage: string;

  @Prop()
  address: string;

  @Prop({ unique: true })
  phone: number;

  @Prop({ unique: true })
  email: string;

  @Prop({ default: 0 })
  freeListingQuota: number;

  @Prop({ default: 0 })
  freeListingQuotaRemaining: number;
}

export const BrokerSchema = SchemaFactory.createForClass(Broker);
