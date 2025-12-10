import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PropertyModule } from './property/property.module';
import { UsersModule } from './users/users.module';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { BrokersModule } from './brokers/brokers.module';
import { AgentsModule } from './agents/agents.module';
import { OwnerModule } from './owner/owner.module';
import { CloudinaryProvider } from './cloudinary/cloudinary.provider';
import { CloudinaryService } from './cloudinary/cloudinary.service';
import { CloudinaryModule } from './cloudinary/cloudinary.module';
import { APP_FILTER } from '@nestjs/core';
import { HttpExceptionFilter } from './utils/http-exception.filter';
import { AuthModule } from './auth/auth.module';
import { FavoriteModule } from './favorite/favorite.module';
import { BrokerRequestModule } from './broker-request/broker-request.module';
import { AdsModule } from './ads/ads.module';
import { PaymentModule } from './payment/payment.module';
import { PackagesModule } from './packages/packages.module';
import { MessagesModule } from './messages/messages.module';
import { ChatModule } from './chat/chat.module';
import { MailModule } from './mail/mail.module';
import { RatingModule } from './rating/rating.module';
import { PropertyTypeModule } from './property-type/property-type.module';
import { AnalyticsModule } from './analytics/analytics.module';
import { FeaturedPropertyModule } from './featured-property/featured-property.module';
import { NotificationModule } from './notification/notification.module';
import { GlobalSettingsModule } from './global-settings/global-settings.module';
import { BrokerPackagesModule } from './broker-packages/broker-packages.module';
import { ReportModule } from './report/report.module';
import { OtpModule } from './otp/otp.module';
// import { ServeStaticModule } from '@nestjs/serve-static/dist/serve-static.module';
// import { join } from 'path';

@Module({
  imports: [
    ConfigModule.forRoot({ envFilePath: '.env', isGlobal: true }),
    MongooseModule.forRoot(process.env.MONGO_URL),
    // ServeStaticModule.forRoot({
    //   rootPath: join(__dirname, '..', 'public'), // serve static assets
    // }),
    PropertyModule,
    UsersModule,
    BrokersModule,
    AgentsModule,
    OwnerModule,
    CloudinaryModule,
    AuthModule,
    FavoriteModule,
    BrokerRequestModule,
    AdsModule,
    PaymentModule,
    PackagesModule,
    MessagesModule,
    ChatModule,
    MailModule,
    RatingModule,
    PropertyTypeModule,
    AnalyticsModule,
    FeaturedPropertyModule,
    NotificationModule,
    GlobalSettingsModule,
    BrokerPackagesModule,
    ReportModule,
    OtpModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    CloudinaryProvider,
    CloudinaryService,
    { provide: APP_FILTER, useClass: HttpExceptionFilter },
  ],
})
// broker
export class AppModule {}
