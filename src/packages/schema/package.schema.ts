import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type PackageDocument = HydratedDocument<Package>;

@Schema({ timestamps: true })
export class Package {
  @Prop({ required: true })
  name: string;

  @Prop()
  description: string;

  @Prop({ required: true })
  maxListingsAllowed: number;

  @Prop({ required: true })
  remining: number;

  @Prop({ required: true })
  price: number;
}

export const PackageSchema = SchemaFactory.createForClass(Package);
