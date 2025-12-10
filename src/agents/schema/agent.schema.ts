import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';
import { Broker } from 'src/brokers/schema/broker.schema';
import { User } from 'src/users/schema/user.schema';

export type AgentDocument = HydratedDocument<Agent>;

@Schema({ timestamps: true })
export class Agent {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Broker', default: null })
  broker: Broker;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  user: User;

  @Prop({ default: null })
  whatsappNumber: string;

  @Prop({ default: false })
  isInHouseAgent: boolean;

  @Prop({ default: false })
  isAdmin: boolean;
}

export const AgentSchema = SchemaFactory.createForClass(Agent);
