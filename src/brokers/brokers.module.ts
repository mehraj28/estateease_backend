import { Module } from '@nestjs/common';
import { BrokersService } from './brokers.service';
import { BrokersController } from './brokers.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Broker, BrokerSchema } from './schema/broker.schema';
import { PaginationService } from 'src/services/pagination.service';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Broker.name, schema: BrokerSchema }]),
  ],
  exports: [
    MongooseModule.forFeature([{ name: Broker.name, schema: BrokerSchema }]),
    BrokersService,
  ],
  controllers: [BrokersController],
  providers: [BrokersService, PaginationService, CloudinaryService],
})
export class BrokersModule {}
