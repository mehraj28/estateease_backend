import { Module } from '@nestjs/common';
import { RatingController } from './rating.controller';
import { RatingService } from './rating.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Rating, RatingSchema } from './schema/rate.schema';
import { UsersModule } from 'src/users/users.module';
import { PaginationService } from 'src/services/pagination.service';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Rating.name, schema: RatingSchema }]),
    UsersModule,
  ],
  exports: [
    MongooseModule.forFeature([{ name: Rating.name, schema: RatingSchema }]),
    RatingService,
  ],
  controllers: [RatingController],
  providers: [RatingService, PaginationService],
})
export class RatingModule {}
