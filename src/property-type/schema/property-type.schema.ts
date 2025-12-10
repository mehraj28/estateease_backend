import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type propertyTypeDocument = HydratedDocument<PropertyType>;

@Schema({ timestamps: true })
export class PropertyType {
  @Prop()
  name: string;

  @Prop({ default: false })
  isDeleted: boolean;
}

export const PropertyTypeSchema = SchemaFactory.createForClass(PropertyType);
