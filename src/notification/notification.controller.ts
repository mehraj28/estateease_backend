import { Controller, Get, Param, Post, Put, Query, Body } from '@nestjs/common';
import { NotificationService } from './notification.service';
import { SendNotificationToAllUsersDto } from './dto/send-notification.dto';

@Controller('notification')
export class NotificationController {
  constructor(private notificationService: NotificationService) {}

  @Post('send')
  async sendNotification() {
    return this.notificationService.sendNotification();
  }

  //send notification to all users
  @Post('push/all-users')
  async sendPushNotificationToAllUsers(
    @Body() data: SendNotificationToAllUsersDto,
  ) {
    return this.notificationService.sendPushNotificationToAllUsers(data);
  }

  //get notification for user
  @Get('user/:id')
  async getNotificationForUser(@Param('id') userId: string) {
    return this.notificationService.getNotificationForUserAndBroker(userId);
  }
  //mark notification as read
  @Put('read/:id')
  async markNotificationAsRead(@Param('id') id: string) {
    return this.notificationService.markNotificationAsRead(id);
  }
  //mark notification as read
  @Put('read/all/:id')
  async markAllNotificationAsRead(@Param('id') id: string) {
    return this.notificationService.markAllNotificationAsRead(id);
  }

  //admin dashboard brokers
  @Get('dashboard/user/:id')
  async getLatestNotificationForDahboard(@Param('id') userId: string) {
    return this.notificationService.getLatestNotificationForDahboard(userId);
  }

  //admin dashboard admin
  @Get('dashboard/admin/:id')
  async getLatestNotificationForAdminDahboard(@Param('id') userId: string) {
    return this.notificationService.getLatestNotificationForAdminDahboard(
      userId,
    );
  }

  //get all notifications for broker and user
  @Get('user/all/:id')
  async getAllNotificationForBrokerAndUser(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Param('id') id: string,
  ) {
    return this.notificationService.getAllNotificationForBrokerAndUser(
      page,
      perPage,
      id,
    );
  }

  //get all notifications for admin
  @Get('admin/all/:id')
  async getAllNotificationForAdmin(
    @Query('page') page = 1,
    @Query('perPage') perPage = 10,
    @Param('id') id: string,
  ) {
    return this.notificationService.getAllNotificationForAdmin(
      page,
      perPage,
      id,
    );
  }
}
