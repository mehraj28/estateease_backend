import { Injectable } from '@nestjs/common';
import { AdsService } from 'src/ads/ads.service';
import { AgentsService } from 'src/agents/agents.service';
import { BrokerPackagesService } from 'src/broker-packages/broker-packages.service';
import { BrokersService } from 'src/brokers/brokers.service';
import { OwnerService } from 'src/owner/owner.service';
import { PaymentService } from 'src/payment/payment.service';
import { PropertyService } from 'src/property/property.service';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AnalyticsService {
  constructor(
    private readonly usersService: UsersService,
    private readonly agentService: AgentsService,
    private readonly brokersService: BrokersService,
    private readonly propertyService: PropertyService,
    private readonly ownersService: OwnerService,
    private readonly adsService: AdsService,
    private readonly paymentService: PaymentService,
    private readonly brokerPackagesService: BrokerPackagesService,
  ) {}

  //broker detail count data
  async brokerDetailCountInfo(brokerId: string) {
    const agentsCount = await this.agentService.getBrokerAgentsCount(brokerId);
    const featuredPropertyCount =
      await this.propertyService.getAllFeaturedPropertyCountOfBroker(brokerId);
    const totalPropertyCount =
      await this.propertyService.getAllPropertyCountOfBroker(brokerId);
    const soldPropertyCount =
      await this.propertyService.getAllSoldPropertyCountOfBroker(brokerId);
    const rentedPropertyCount =
      await this.propertyService.getAllRentedPropertyCountOfBroker(brokerId);
    const adsCount = await this.adsService.getAdsCountForBroker(brokerId);
    const totalPackagesCount =
      await this.brokerPackagesService.totalPackagesOfBroker(brokerId);
    const totalMoneySpent = await this.paymentService.totalMoneySpentOfBroker(
      brokerId,
    );
    return {
      agentsCount,
      featuredPropertyCount,
      totalPropertyCount,
      soldPropertyCount,
      rentedPropertyCount,
      adsCount,
      totalPackagesCount,
      totalMoneySpent,
    };
  }
  //********************* admin dashboard api ****************************/
  async getDashboardDataCount() {
    const usersCount = await this.usersService.getUsersCount();
    const agentsCount = await this.agentService.getAgentsCount();
    const brokersCount = await this.brokersService.getBrokersCount();
    const ownersCount = await this.ownersService.getOwnersCount();
    const inHousePropertyCount =
      await this.propertyService.getAllInHousePropertyCount();
    const getAllRentedPropertyCount =
      await this.propertyService.getAllRentedPropertyCount();
    const getAllSoldPropertyCount =
      await this.propertyService.getAllSoldPropertyCount();
    const brokersPropertyCount =
      await this.propertyService.getAllBrokersPropertyCount();
    const featuredPropertyCount =
      await this.propertyService.getAllFeaturedPropertyCount();
    const adsCount = await this.adsService.getAdsCount();
    const paymentCount = await this.paymentService.totalMoneyGot();
    return {
      usersCount,
      agentsCount,
      brokersCount,
      inHousePropertyCount,
      brokersPropertyCount,
      featuredPropertyCount,
      getAllRentedPropertyCount,
      getAllSoldPropertyCount,
      ownersCount,
      adsCount,
      paymentCount,
    };
  }

  //********************* brokers dashboard api ****************************/
  async getBrokersDashboardDataCount(brokerId: string) {
    const agentsCount = await this.agentService.getBrokerAgentsCount(brokerId);
    const adsCount = await this.adsService.getAdsCountForBroker(brokerId);
    const featuredPropertyCount =
      await this.propertyService.getAllFeaturedPropertyCountOfBroker(brokerId);
    const totalPropertyCount =
      await this.propertyService.getAllPropertyCountOfBroker(brokerId);
    const soldPropertyCount =
      await this.propertyService.getAllSoldPropertyCountOfBroker(brokerId);
    const rentedPropertyCount =
      await this.propertyService.getAllRentedPropertyCountOfBroker(brokerId);
    return {
      agentsCount,
      featuredPropertyCount,
      adsCount,
      totalPropertyCount,
      soldPropertyCount,
      rentedPropertyCount,
    };
  }

  async getPropertyAnalyticForBroker(brokerId: string) {
    const data = await this.propertyService.getPropertyAnalyticForBroker(
      brokerId,
    );
    return data;
  }
}
