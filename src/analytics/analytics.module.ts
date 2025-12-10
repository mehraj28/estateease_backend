import { Module } from '@nestjs/common';
import { AnalyticsController } from './analytics.controller';
import { AnalyticsService } from './analytics.service';
import { UsersModule } from 'src/users/users.module';
import { OwnerModule } from 'src/owner/owner.module';
import { AdsModule } from 'src/ads/ads.module';
import { BrokersModule } from 'src/brokers/brokers.module';
import { PaymentModule } from 'src/payment/payment.module';
import { AgentsModule } from 'src/agents/agents.module';
import { PropertyModule } from 'src/property/property.module';
import { BrokerPackagesModule } from 'src/broker-packages/broker-packages.module';

@Module({
  imports: [
    UsersModule,
    PaymentModule,
    PropertyModule,
    OwnerModule,
    AdsModule,
    AgentsModule,
    BrokersModule,
    BrokerPackagesModule,
  ],
  controllers: [AnalyticsController],
  providers: [AnalyticsService],
})
export class AnalyticsModule {}
