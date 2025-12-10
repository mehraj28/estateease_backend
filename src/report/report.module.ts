import { Module } from '@nestjs/common';
import { ReportController } from './report.controller';
import { ReportService } from './report.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Report, ReportSchema } from './schema/report.schema';
import { UsersModule } from 'src/users/users.module';
import { PropertyModule } from 'src/property/property.module';
import { NotificationModule } from 'src/notification/notification.module';
import { SendPropertyReportNotificationAndEmailInterceptor } from 'src/interceptors/notification.interceptors';
import { PaginationService } from 'src/services/pagination.service';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Report.name, schema: ReportSchema }]),
    UsersModule,
    PropertyModule,
    NotificationModule,
  ],
  controllers: [ReportController],
  providers: [
    ReportService,
    SendPropertyReportNotificationAndEmailInterceptor,
    PaginationService,
  ],
})
export class ReportModule {}
