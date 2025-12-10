import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { AnalyticsService } from './analytics.service';
import { Roles } from 'src/guards/role.decorator';
import { Role } from 'src/utils/role.enum';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';

@Controller('analytics')
export class AnalyticsController {
  constructor(private analyticsService: AnalyticsService) {}

  //  ************************admin dashboard api ************************/
  @Get('admin-dashboard')
  // @UseGuards(JwtAuthGuard, RoleGuard)
  // @Roles(Role.Admin)
  async getDashboardDataCount() {
    const dashboardData = await this.analyticsService.getDashboardDataCount();
    return dashboardData;
  }
  @Get('broker-detail/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async brokerDetailCountInfo(@Param('id') id: string) {
    const dashboardData = await this.analyticsService.brokerDetailCountInfo(id);
    return dashboardData;
  }

  //  ************************broker dashboard api ************************/
  @Get('broker/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker)
  async getBrokersDashboardDataCount(@Param('id') id: string) {
    const dashboardData =
      await this.analyticsService.getBrokersDashboardDataCount(id);
    return dashboardData;
  }

  @Get('property/broker/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker)
  async getPropertyAnalyticForBroker(@Param('id') id: string) {
    return await this.analyticsService.getPropertyAnalyticForBroker(id);
  }
}
