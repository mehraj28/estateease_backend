import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type GlobalSettingDocument = HydratedDocument<GlobalSetting>;

@Schema({ timestamps: true })
export class GlobalSetting {
  @Prop({ default: 0 })
  bannedAdPrice: number;

  @Prop({ default: 0 })
  propertyAdPrice: number;

  @Prop({ default: 1000 })
  propertyAdViewRange: number;

  // app logo name and setting
  @Prop({ required: true })
  appLogo: string;

  @Prop({ required: true })
  appName: string;

  @Prop({ required: true })
  dashboardUrl: string;
}

export const GlobalSettingSchema = SchemaFactory.createForClass(GlobalSetting);
