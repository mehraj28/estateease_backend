import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type BrokerDocument = HydratedDocument<Owner>;

@Schema({ timestamps: true })
export class Owner {
  @Prop({ required: true, unique: true, trim: true })
  name: string;

  @Prop()
  logo: string;

  @Prop({ trim: true })
  address: string;

  @Prop({ required: true, unique: true })
  phone: string;

  @Prop({ unique: true, trim: true })
  email: string;
}

export const OwnerSchema = SchemaFactory.createForClass(Owner);
