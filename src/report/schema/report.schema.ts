import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { Property } from 'src/property/schema/property.schema';
import { User } from 'src/users/schema/user.schema';
import { ReportPropertyAction } from 'src/utils/actions.enum';

export type ReportDocument = HydratedDocument<Report>;

@Schema({ timestamps: true })
export class Report {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  })
  user: User;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Property',
    required: true,
  })
  property: Property;

  @Prop({ required: true })
  discription: string;

  @Prop({ default: ReportPropertyAction.NEW })
  status: ReportPropertyAction;
}

export const ReportSchema = SchemaFactory.createForClass(Report);
