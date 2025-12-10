import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import {
  SendAdsNotificationForAdmin,
  SendAdsNotificationForBroker,
  SendBrokerRequestNotificationForAdmin,
  SendBrokerRequestNotificationForBroker,
  SendFeaturedPropertyNotificationForAdmin,
  SendFeaturedPropertyNotificationForBroker,
  SendListingPackagetNotificationForAdmin,
  SendListingPackagetNotificationForBroker,
  SendPropertyReportNotificationForAdmin,
  SendPropertyReportNotificationForBroker,
} from 'src/notification/dto/send-notification.dto';
import { NotificationService } from 'src/notification/notification.service';
import { UsersService } from 'src/users/users.service';
import {
  AdsAction,
  BrokerRequestAction,
  FeaturePropertyAction,
  ListingPackageAction,
  PropertyReporttAction,
  ReportPropertyAction,
} from 'src/utils/actions.enum';
import { NotificationPriority } from 'src/utils/notifications.enum';

@Injectable()
export class SendAdsNotificationAndEmailInterceptor implements NestInterceptor {
  constructor(
    private usersService: UsersService,
    private notificationService: NotificationService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      tap((response) => {
        if (response?.data && response.type === AdsAction.CREATE) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to admin
            const admins = await this.usersService.findAllAdmins();
            const adminEmails = await this.usersService.findAllAdminsEmail();
            const notificationData: SendAdsNotificationForAdmin = {
              ads: response?.data._id.toString(),
              title: 'You have new ads request',
              body: response?.data.title,
              recipients: admins,
              recipients_email: adminEmails,
              priority: NotificationPriority.NORMAL,
              data: response?.data,
            };
            this.notificationService.sendAdsRequestNotificationToAdmin(
              notificationData,
            );
          });
        }
        if (response?.data && response.type === AdsAction.APPROVE) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to admin
            const broker = await this.usersService.getUserEmailByBrokerId(
              response?.data?.broker,
            );
            const user = await this.usersService.getUserByBrokerId(
              response?.data?.broker,
            );
            const notificationData: SendAdsNotificationForBroker = {
              ads: response?.data._id.toString(),
              title: `Congragulation Your Ads ${response.data.adTitle} is Approved`,
              body: response?.data.title,
              user: user,
              recipient_email: broker,
              priority: NotificationPriority.NORMAL,
              data: response?.data,
            };
            this.notificationService.sendAdsRequestApprovalNotificationToBroker(
              notificationData,
            );
          });
        }
      }),
    );
  }
}

@Injectable()
export class SendFeaturePropertyNotificationAndEmailInterceptor
  implements NestInterceptor
{
  constructor(
    private usersService: UsersService,
    private notificationService: NotificationService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      tap((response) => {
        if (response?.data && response.type === FeaturePropertyAction.CREATE) {
          // Perform the update operation in a separate event loop

          setImmediate(async () => {
            //send notification to admin
            const admins = await this.usersService.findAllAdmins();
            const adminEmails = await this.usersService.findAllAdminsEmail();
            const notificationData: SendFeaturedPropertyNotificationForAdmin = {
              featuredProperty: response?.data[0]._id,
              title: 'You have new properts ads request',
              body: response?.data[0].property?.name,
              recipients: admins,
              recipients_email: adminEmails,
              priority: NotificationPriority.NORMAL,
              data: response?.data[0],
            };
            this.notificationService.sendFeaturedPropertyRequestNotificationToAdmin(
              notificationData,
            );
          });
        }
        if (response?.data && response.type === FeaturePropertyAction.APPROVE) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to broker
            const broker = await this.usersService.getUserEmailByBrokerId(
              response?.data?.broker,
            );
            const user = await this.usersService.getUserByBrokerId(
              response?.data?.broker,
            );
            const notificationData: SendFeaturedPropertyNotificationForBroker =
              {
                featuredProperty: response?.data._id,
                title: 'Your property Ads request has been approved',
                body: response?.data.property.name,
                user: user,
                recipient_email: broker.email,
                priority: NotificationPriority.NORMAL,
                data: response?.data,
              };
            this.notificationService.sendFeaturedPropertyRequestApprovalNotificationToBroker(
              notificationData,
            );
          });
        }
      }),
    );
  }
}

@Injectable()
export class SendBrokerRequestNotificationAndEmailInterceptor
  implements NestInterceptor
{
  constructor(
    private usersService: UsersService,
    private notificationService: NotificationService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      tap((response) => {
        if (response?.data && response.type === BrokerRequestAction.CREATE) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to admin
            const admins = await this.usersService.findAllAdmins();
            const adminEmails = await this.usersService.findAllAdminsEmail();
            const notificationData: SendBrokerRequestNotificationForAdmin = {
              broker_request: response?.data._id,
              title: 'You have new broker request',
              body: response?.data.companyName,
              recipients: admins,
              recipients_email: adminEmails,
              priority: NotificationPriority.NORMAL,
              data: response?.data,
            };
            this.notificationService.sendBrokerRequestNotificationToAdmin(
              notificationData,
            );
          });
        }
        if (response?.data && response.type === BrokerRequestAction.APPROVE) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to admin
            const user = await this.usersService.getUserEmailByUserId(
              response?.data?.user,
            );

            const notificationData: SendBrokerRequestNotificationForBroker = {
              broker_request: response?.data._id,
              title: 'You company request has been approved',
              body: response?.data.companyName,
              user: response?.data.user,
              recipient_email: user?.email,
              priority: NotificationPriority.NORMAL,
              data: response?.data,
            };
            this.notificationService.sendBrokerRequestApprovalNotificationToBroker(
              notificationData,
            );
          });
        }
        //rejection
        if (response?.data && response.type === BrokerRequestAction.REJECT) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to admin
            const user = await this.usersService.getUserEmailByUserId(
              response?.data?.rejectRequest?.user,
            );
            console.log(response);
            const notificationData: SendBrokerRequestNotificationForBroker = {
              broker_request: response?.data?.rejectRequest._id,
              title: 'You request has been Rejected',
              body:
                response?.data?.message ??
                'Please Check Your input and resend ur request',
              user: response?.data?.rejectRequest?.user,
              recipient_email: user?.email,
              priority: NotificationPriority.NORMAL,
              data: response?.data,
            };
            console.log(notificationData);
            this.notificationService.sendBrokerRequestRejectionNotificationToBroker(
              notificationData,
            );
          });
        }
      }),
    );
  }
}

@Injectable()
export class SendPropertyReportNotificationAndEmailInterceptor
  implements NestInterceptor
{
  constructor(
    private usersService: UsersService,
    private notificationService: NotificationService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      tap((response) => {
        if (response?.data && response.type === PropertyReporttAction.CREATE) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to admin
            const admins = await this.usersService.findAllAdmins();
            const adminEmails = await this.usersService.findAllAdminsEmail();
            const notificationData: SendPropertyReportNotificationForAdmin = {
              report: response?.data._id,
              title: `new Property report by ${response.data.user.firstName} on ${response.data.property.name} `,
              body: response.data?.discription,
              recipients: admins,
              recipients_email: adminEmails,
              priority: NotificationPriority.HIGH,
              data: response?.data,
            };
            this.notificationService.sendPropertyReportNotificationToAdmin(
              notificationData,
            );
          });
        }
        if (response?.data && response.type === BrokerRequestAction.APPROVE) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to admin
            const user = await this.usersService.getUserEmailByUserId(
              response?.data?.user,
            );

            const notificationData: SendBrokerRequestNotificationForBroker = {
              broker_request: response?.data._id,
              title: 'You company request has been approved',
              body: response?.data.companyName,
              user: response?.data.user,
              recipient_email: user?.email,
              priority: NotificationPriority.NORMAL,
              data: response?.data,
            };
            this.notificationService.sendBrokerRequestApprovalNotificationToBroker(
              notificationData,
            );
          });
        }
      }),
    );
  }
}

@Injectable()
export class SendListingPackageNotificationAndEmailInterceptor
  implements NestInterceptor
{
  constructor(
    private usersService: UsersService,
    private notificationService: NotificationService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      tap((response) => {
        if (response?.data && response.type === ListingPackageAction.CREATE) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to admin
            const admins = await this.usersService.findAllAdmins();
            const adminEmails = await this.usersService.findAllAdminsEmail();
            const notificationData: SendListingPackagetNotificationForAdmin = {
              broker_package: response?.data._id,
              title: 'You have new listing package request',
              body: response.data?.package?.name,
              recipients: admins,
              recipients_email: adminEmails,
              priority: NotificationPriority.HIGH,
              data: response?.data,
            };
            this.notificationService.sendListingPackageNotificationToAdmin(
              notificationData,
            );
          });
        }
        if (response?.data && response.type === ListingPackageAction.APPROVE) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to admin
            const user = await this.usersService.getUserEmailByUserId(
              response?.data?.user,
            );

            const notificationData: SendListingPackagetNotificationForBroker = {
              broker_package: response?.data._id,
              title: 'You Listing Package is Activated',
              body: response.data?.package?.name,
              user: response?.data.user,
              recipient_email: user?.email,
              priority: NotificationPriority.NORMAL,
              data: response?.data,
            };
            this.notificationService.sendListingPackageApprovalNotificationToBroker(
              notificationData,
            );
          });
        }
      }),
    );
  }
}

//send notification when admin hide the property because fof report smh stuff
@Injectable()
export class SendReportNotificationAndEmailInterceptorForBroker
  implements NestInterceptor
{
  constructor(
    private usersService: UsersService,
    private notificationService: NotificationService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      tap((response) => {
        if (response?.data && response.type === ReportPropertyAction.PENDING) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to broker
            const user = await this.usersService.findUserByBrokerId(
              response?.data?.property.broker,
            );
            const notificationData: SendPropertyReportNotificationForBroker = {
              report: response?.data.property?._id,
              title: `Your Property  ${response?.data.property?.name} temporary hidden`,
              body: response?.message,
              user: user._id,
              recipient_email: user?.email,
              priority: NotificationPriority.HIGH,
              data: response?.data,
            };
            this.notificationService.sendReportNotificationToBroker(
              notificationData,
            );
          });
        }
        if (response?.data && response.type === ReportPropertyAction.APPROVED) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to user
            const user = await this.usersService.findUserByBrokerId(
              response?.data?.property.broker,
            );
            const notificationData: SendPropertyReportNotificationForBroker = {
              report: response?.data.property?._id,
              title: `Your Property  ${response?.data.property?.name} now active`,
              body: `Your Property  ${response?.data.property?.name} previously hidden due to report is now publicly visible `,
              user: user._id,
              recipient_email: user?.email,
              priority: NotificationPriority.HIGH,
              data: response?.data,
            };
            this.notificationService.sendReportNotificationToBroker(
              notificationData,
            );
          });
        }
        //rejection
        if (response?.data && response.type === BrokerRequestAction.REJECT) {
          // Perform the update operation in a separate event loop
          setImmediate(async () => {
            //send notification to admin
            const user = await this.usersService.getUserEmailByUserId(
              response?.data?.rejectRequest?.user,
            );

            const notificationData: SendBrokerRequestNotificationForBroker = {
              broker_request: response?.data?.rejectRequest._id,
              title: 'You request has been Rejected',
              body: response?.data?.message,
              user: response?.data.user,
              recipient_email: user?.email,
              priority: NotificationPriority.NORMAL,
              data: response?.data,
            };
            this.notificationService.sendBrokerRequestRejectionNotificationToBroker(
              notificationData,
            );
          });
        }
      }),
    );
  }
}
