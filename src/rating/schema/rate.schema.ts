import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { Property } from 'src/property/schema/property.schema';
import { User } from 'src/users/schema/user.schema';

export type RatingDocument = HydratedDocument<Rating>;

@Schema({ timestamps: true })
export class Rating {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  user: User;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Property' })
  property: Property;

  @Prop({ default: null })
  review: string;

  @Prop({ min: 1, max: 5, required: true })
  rate: number;
}

export const RatingSchema = SchemaFactory.createForClass(Rating);
