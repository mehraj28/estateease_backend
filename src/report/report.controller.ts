import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Put,
  Query,
  UseInterceptors,
  UseGuards,
} from '@nestjs/common';
import { ReportService } from './report.service';
import {
  HideReportPropertyDto,
  ReportPropertyDto,
} from './dto/report-property.dto';
import {
  SendPropertyReportNotificationAndEmailInterceptor,
  SendReportNotificationAndEmailInterceptorForBroker,
} from 'src/interceptors/notification.interceptors';
import { ReportPropertyAction } from 'src/utils/actions.enum';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Role } from 'src/utils/role.enum';
import { Roles } from 'src/guards/role.decorator';

@Controller('report')
export class ReportController {
  constructor(private readonly reportService: ReportService) {}

  //report property by user
  @Post('property/user')
  @UseInterceptors(SendPropertyReportNotificationAndEmailInterceptor)
  async reportProperty(@Body() data: ReportPropertyDto) {
    return await this.reportService.reportProperty(data);
  }

  //get all repoted properties by admin
  @Get('/admin/all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllReportedPropertiesForAdmin(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Query('type') type: ReportPropertyAction,
  ) {
    return await this.reportService.getAllReportedPropertiesForAdmin(
      page,
      perPage,
      type,
    );
  } //get report detail
  @Get('detail/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin, Role.Broker)
  async reportedPropertyDetail(@Param('id') id: string) {
    return await this.reportService.reportedPropertyDetail(id);
  }

  //hide reported property by admin
  @Put('hide-property/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(SendReportNotificationAndEmailInterceptorForBroker)
  async temporaryHideThePropertyByAdmin(
    @Param('id') id: string,
    @Body() data: HideReportPropertyDto,
  ) {
    return await this.reportService.temporaryHideThePropertyByAdmin(id, data);
  }

  // /make the hidden property visible
  @Put('visible-property/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(SendReportNotificationAndEmailInterceptorForBroker)
  async makeThePropertyVisibleThePropertyByAdmin(@Param('id') id: string) {
    return await this.reportService.makeThePropertyVisibleThePropertyByAdmin(
      id,
    );
  }
  // /request for approval by admin  made by broker
  @Put('request-approval/:id')
  @UseInterceptors(SendReportNotificationAndEmailInterceptorForBroker)
  async makeRequestForApproveToAdmin(@Param('id') id: string) {
    return await this.reportService.makeRequestForApproveToAdmin(id);
  }
}
