import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Notification } from './schema/notification.schema';
import { Model } from 'mongoose';
import { OneSignalPushNotificationService } from 'src/services/push-notification.service';
import {
  SendAdsNotificationForAdmin,
  SendAdsNotificationForBroker,
  SendBrokerRequestNotificationForAdmin,
  SendBrokerRequestNotificationForBroker,
  SendFeaturedPropertyNotificationForAdmin,
  SendFeaturedPropertyNotificationForBroker,
  SendListingPackagetNotificationForAdmin,
  SendListingPackagetNotificationForBroker,
  SendNotificationToAllUsersDto,
  SendPropertyReportNotificationForAdmin,
  SendPropertyReportNotificationForBroker,
} from './dto/send-notification.dto';
import { MailService } from 'src/services/mail.service';
import { PaginationService } from 'src/services/pagination.service';
import { GlobalSettingsService } from 'src/global-settings/global-settings.service';

@Injectable()
export class NotificationService {
  constructor(
    @InjectModel(Notification.name)
    private readonly notificationModel: Model<Notification>,
    private readonly pushNotificationService: OneSignalPushNotificationService,
    private readonly mailService: MailService,
    private readonly paginationService: PaginationService,
    private readonly globalSettingsService: GlobalSettingsService,
  ) {}

  async sendNotification() {
    return this.pushNotificationService.pushNotificationToSingleUser({
      message: 'test',
      deviceId: '2b75365c-9a88-4be7-b810-9a8989b653c9',
      appIcon:
        'https://res.cloudinary.com/dxrvoxbvu/image/upload/v1697134985/okc2ubonp8pgrqgx0tnv.jpg',
    });
  }
  async sendPushNotificationToAllUsers(data: SendNotificationToAllUsersDto) {
    const settingsData = await this.globalSettingsService.getGlobalSetting();
    await this.pushNotificationService.pushNotificationToAllUsers({
      appIcon: settingsData.appLogo,
      message: data.desciption,
      bigPicture:
        'https://res.cloudinary.com/dxrvoxbvu/image/upload/v1697134985/okc2ubonp8pgrqgx0tnv.jpg',
    });
    return 'Notification Sent!';
  }

  //============================================================= Admin Notification =========================================================
  //send notification when ads request is made
  async sendAdsRequestNotificationToAdmin(data: SendAdsNotificationForAdmin) {
    await this.notificationModel.create(data);
    const setting = await this.globalSettingsService.getGlobalSetting();
    await this.mailService.sendAdRequestEmailToAdmins({
      recipients: data.recipients_email,
      broker: data?.data?.broker?.name,
      adTitle: data?.data?.title,
      adImage: data?.data?.image,
      startDate: data?.data?.startDate,
      endDate: data?.data?.endDate,
      appLogo: setting.appLogo,
      dashboardUrl: setting.dashboardUrl,
    });
    return;
  }

  //send notification to admin when featured property request is made
  async sendFeaturedPropertyRequestNotificationToAdmin(
    data: SendFeaturedPropertyNotificationForAdmin,
  ) {
    await this.notificationModel.create(data);
    const setting = await this.globalSettingsService.getGlobalSetting();
    await this.mailService.sendPropertyAdRequestEmailToAdmins({
      recipients: data.recipients_email,
      name: data.data.property.name,
      image: data.data.property.images[0].url,
      broker: data.data.property.broker.name ?? data.data?.broker.name,
      appLogo: setting.appLogo,
      dashboardUrl: setting.dashboardUrl,
    });
    return;
  }

  //send notification to admin when broker request is made
  async sendBrokerRequestNotificationToAdmin(
    data: SendBrokerRequestNotificationForAdmin,
  ) {
    await this.notificationModel.create(data);
    const setting = await this.globalSettingsService.getGlobalSetting();
    await this.mailService.sendBrokerRequestEmailToAdmins({
      recipients: data.recipients_email,
      companyLogo: data.data.logo,
      companyAddress: data.data.address,
      companyEmail: data.data.email,
      companyPhone: data.data.phone,
      companyName: data.data.companyName,
      appLogo: setting.appLogo,
      dashboardUrl: setting.dashboardUrl,
    });
    return;
  }

  //send property report to admin
  async sendPropertyReportNotificationToAdmin(
    data: SendPropertyReportNotificationForAdmin,
  ) {
    await this.notificationModel.create(data);
    const setting = await this.globalSettingsService.getGlobalSetting();
    await this.mailService.sendPropertyReportEmailToAdmins({
      recipients: data.recipients_email,
      userName: data.data.user.firstName + ' ' + data.data.user.lastName,
      propertyName: data.data.property.name,
      reason: data.data?.discription,
      price: data.data.property.price,
      appLogo: setting.appLogo,
    });
    return;
  }

  //send listing package approval request from broker to admin
  async sendListingPackageNotificationToAdmin(
    data: SendListingPackagetNotificationForAdmin,
  ) {
    await this.notificationModel.create(data);
    const setting = await this.globalSettingsService.getGlobalSetting();
    await this.mailService.sendPackageRequestEmailToAdmins({
      recipients: data.recipients_email,
      packageName: data.data.package.name,
      brokerLogo: data.data?.broker?.logo,
      maxListing: data.data.package.maxListingsAllowed,
      price: data.data.package.price,
      broker: data.data.broker.name,
      appLogo: setting.appLogo,
      dashboardUrl: setting.dashboardUrl,
    });
    return;
  }
  //============================================================= Broker Notification =========================================================
  //send notification to broker when ads request is accepted
  async sendAdsRequestApprovalNotificationToBroker(
    data: SendAdsNotificationForBroker,
  ) {
    await this.notificationModel.create(data);
    const setting = await this.globalSettingsService.getGlobalSetting();
    await this.mailService.sendAdsApprovalEmailToBroker({
      recipient: data.recipient_email,
      adTitle: data?.data?.title,
      adImage: data?.data?.image,
      startDate: data?.data?.startDate,
      endDate: data?.data?.endDate,
      appLogo: setting.appLogo,
    });
    return;
  }

  //send notification to broker when featured property request is accepted
  async sendFeaturedPropertyRequestApprovalNotificationToBroker(
    data: SendFeaturedPropertyNotificationForBroker,
  ) {
    // console.log(data);
    const setting = await this.globalSettingsService.getGlobalSetting();
    await this.notificationModel.create(data);
    await this.mailService.sendPropertyAdsApprovalEmailToBroker({
      recipient: data.recipient_email,
      name: data.data.property.name,
      image: data.data.property.images[0].url,
      appLogo: setting.appLogo,
      dashboardUrl: setting.dashboardUrl,
    });
    return;
  }
  //send notification to broker when his request is accepted
  async sendBrokerRequestApprovalNotificationToBroker(
    data: SendBrokerRequestNotificationForBroker,
  ) {
    await this.notificationModel.create(data);
    const setting = await this.globalSettingsService.getGlobalSetting();
    await this.mailService.sendRequestApprovalEmailToBroker({
      recipient: data.recipient_email,
      companyLogo: data.data.logo,
      companyAddress: data.data.address,
      companyEmail: data.data.email,
      companyPhone: data.data.phone,
      companyName: data.data.companyName,
      dashboardUrl: setting.dashboardUrl,
      appLogo: setting.appLogo,
      reason: 'Congratulations! Your Company request has been approved.',
    });
    return;
  }
  //send notification to broker when his request is rejected
  async sendBrokerRequestRejectionNotificationToBroker(
    data: SendBrokerRequestNotificationForBroker,
  ) {
    await this.notificationModel.create(data);
    const setting = await this.globalSettingsService.getGlobalSetting();
    await this.mailService.sendRequestRejectEmailToBroker({
      recipient: data.recipient_email,
      companyLogo: data.data.rejectRequest?.logo,
      companyAddress: data.data.rejectRequest?.address,
      companyEmail: data.data.rejectRequest?.email,
      companyPhone: data.data.rejectRequest?.phone,
      companyName: data.data.rejectRequest?.companyName,
      reason: data.data.message,
      appLogo: setting.appLogo,
    });
    return;
  }

  //send listing package approval to broker
  async sendListingPackageApprovalNotificationToBroker(
    data: SendListingPackagetNotificationForBroker,
  ) {
    await this.notificationModel.create(data);
    const setting = await this.globalSettingsService.getGlobalSetting();
    await this.mailService.sendListingPackageApprovalEmailToBroker({
      recipient: data.recipient_email,
      packageName: data.data.package.name,
      remining: data.data.package.remining,
      maxListing: data.data.package.maxListingsAllowed,
      appLogo: setting.appLogo,
      dashboardUrl: setting.dashboardUrl,
    });
    return;
  }

  //send notification about hiddden by admin
  async sendReportNotificationToBroker(
    data: SendPropertyReportNotificationForBroker,
  ) {
    await this.notificationModel.create(data);
    const setting = await this.globalSettingsService.getGlobalSetting();
    await this.mailService.sendPropertyReportHiddenEmailToBroker({
      recipient: data.recipient_email,
      propertyName: data.data.property.name,
      message: data.body,
      appLogo: setting.appLogo,
      dashboardUrl: setting.dashboardUrl,
    });
    return;
  }
  //***************user notification *************/

  async getNotificationForUserAndBroker(id: string) {
    const notifications = await this.notificationModel.find({ user: id }).sort({
      createdAt: -1,
    });
    const unreadNotifications = await this.notificationModel
      .find()
      .countDocuments({
        user: id,
        readAt: null,
      });
    return { notifications, unreadNotifications };
  }

  //mark notification as read
  async markNotificationAsRead(id: string) {
    const notification = await this.notificationModel.findById(id);
    notification.readAt = new Date();
    await notification.save();
    return notification;
  }
  //mark all notification as read
  async markAllNotificationAsRead(id: string) {
    const notifications = await this.notificationModel.updateMany(
      { $or: [{ user: id }, { recipients: { $in: [id] } }] },
      { readAt: new Date() },
      { multi: true, new: true },
    );
    return notifications;
  }
  //=========================dashboard usesage api ===================//
  async getLatestNotificationForDahboard(id: string) {
    const unreadNotfCount = await this.notificationModel
      .find()
      .countDocuments({ user: id, readAt: null });
    const notifications = await this.notificationModel
      .find({ user: id })
      .sort({ createdAt: -1 })
      .limit(5);
    return { unreadNotfCount, notifications };
  }
  //send notifications for admin
  async getLatestNotificationForAdminDahboard(id: string) {
    const unreadNotfCount = await this.notificationModel
      .find()
      .countDocuments({ recipients: { $in: [id] }, readAt: null });
    const notifications = await this.notificationModel
      .find({ recipients: { $in: [id] } })
      .sort({ createdAt: -1 })
      .limit(5);
    return { unreadNotfCount, notifications };
  }
  //get paginated notification for dashboard broker and user
  async getAllNotificationForBrokerAndUser(
    page: number,
    perPage: number,
    id: string,
  ) {
    const allNotifications = await this.notificationModel.find({
      user: id,
    });
    const totalNotifications = allNotifications.length;
    const paginatedData = this.paginationService.paginate(
      allNotifications,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalNotifications,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalNotifications,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
  async getAllNotificationForAdmin(page: number, perPage: number, id: string) {
    const allNotifications = await this.notificationModel.find({
      recipients: { $in: [id] },
    });
    const totalNotifications = allNotifications.length;
    const paginatedData = this.paginationService.paginate(
      allNotifications,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalNotifications,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalNotifications,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
}
