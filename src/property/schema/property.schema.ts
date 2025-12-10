import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import * as mongoose from 'mongoose';
import { HydratedDocument } from 'mongoose';
import { Broker } from '../../brokers/schema/broker.schema';
import { Owner } from '../../owner/schema/owner.schema';
import { Agent } from 'src/agents/schema/agent.schema';
import { PropertyTypes } from 'src/utils/property.enum';
import { User } from 'src/users/schema/user.schema';
import { PropertyType } from 'src/property-type/schema/property-type.schema';
export type PropertyDocument = HydratedDocument<Property>;
export type PropertyImagesDocument = HydratedDocument<PropertyImages>;
export type PropertyAddressDocument = HydratedDocument<AddressDocument>;
export type PropertyFacilitiesDocument = HydratedDocument<PropertyFacilities>;

@Schema()
class PropertyImages {
  @Prop()
  url: string;
}

const PropertyImagesSchema = SchemaFactory.createForClass(PropertyImages);

//facilities
@Schema()
class PropertyFacilities {
  @Prop()
  facility: string;

  @Prop({ required: true })
  distance: number;
}
@Schema()
class AddressDocument {
  @Prop({ required: true })
  city: string;

  @Prop({ required: true })
  location: string;

  @Prop({ type: [Number], required: true })
  loc: number[];
}
const AddressDocumentSchema = SchemaFactory.createForClass(
  AddressDocument,
).index({ loc: '2dsphere' });

@Schema()
class PropertyDetails {
  @Prop({ required: true })
  area: number;

  @Prop({ required: true })
  bedroom: number;

  @Prop({ required: true })
  bathroom: number;

  @Prop({ required: true })
  yearBuilt: number;

  @Prop({ default: null })
  floor: number;
}

@Schema({ timestamps: true })
export class Property {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Broker', default: null })
  broker: Broker;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  poster: User; //who post the property

  @Prop({ required: true })
  name: string;

  @Prop([PropertyImagesSchema])
  images: PropertyImages[];

  @Prop({ default: null })
  VideoTour: string;

  @Prop({ required: true })
  price: number;

  @Prop({ required: true })
  currency: string;

  @Prop({ required: true })
  description: string;

  @Prop()
  paymentDescription: string;

  @Prop({ required: true }) //sell or rent
  propertyType: PropertyTypes;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'PropertyType',
    required: true,
  }) //villa or other type
  propertyHomeType: PropertyType;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Owner', required: true })
  owner: Owner;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Agent', required: true })
  agent: Agent;

  @Prop({ type: PropertyDetails, required: true })
  details: PropertyDetails;

  @Prop({ default: 0 })
  views: number;

  @Prop(AddressDocumentSchema)
  address: AddressDocument;

  @Prop([PropertyFacilities])
  facilities: PropertyFacilities[];

  @Prop()
  amenities: string[];

  @Prop({ select: false })
  rentedDays: string[]; //for analytics purpose noting to do with customer side

  @Prop({ default: false })
  isFeatured: boolean;

  @Prop({ default: false })
  isRented: boolean;

  @Prop({ default: false })
  isFurnished: boolean;

  @Prop({ default: false })
  isSoldOut: boolean;

  @Prop({ default: false })
  isInHouseProperty: boolean;

  @Prop({ default: false })
  isHide: boolean; //if the poster hide from the user view of the customer

  @Prop({ default: false })
  isHiddenByAdmin: boolean; //if the admin hide from the user view of the customer like becose of spam report by user

  @Prop({ default: false })
  isApproved: boolean;

  @Prop({ default: true }) //check if the poster don't fnish the property like save as for later to push
  isPublished: boolean;

  @Prop({ default: false }) //this is for soft delete
  isDeleted: boolean;
}

export const PropertySchema = SchemaFactory.createForClass(Property);
PropertySchema.index({ propertyType: 1, propertyHomeType: 1 });
