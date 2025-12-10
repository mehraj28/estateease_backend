import {
  IsString,
  IsNotEmpty,
  IsEnum,
  IsArray,
  IsOptional,
  IsObject,
} from 'class-validator';
import {
  NotificationPriority,
  NotificationSender,
} from 'src/utils/notifications.enum';

export class SendNotificationToAllUsersDto {
  @IsNotEmpty()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsString()
  desciption: string;
}
export class SendNotificationDto {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  user: string;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  payment: string;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  property: string;
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  featuredProperty: string;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  ads: string;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  broker_request: string;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  report: string;

  @IsNotEmpty()
  @IsString()
  @IsOptional()
  broker_package: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  body: string;

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  recipients: string[];

  @IsOptional()
  @IsEnum(NotificationSender, { message: 'invalid sender type' })
  sender: NotificationSender;

  @IsOptional()
  @IsEnum(NotificationPriority, { message: 'invalid priority type' })
  priority: NotificationPriority;
}

//-------------------admin notification-------------------//broker_request
export class SendAdsNotificationForAdmin {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  ads: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  body: string;

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  recipients: string[];

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  recipients_email: string[];

  @IsOptional()
  @IsNotEmpty()
  @IsEnum(NotificationPriority, { message: 'invalid priority type' })
  priority: NotificationPriority;

  @IsNotEmpty()
  @IsOptional()
  @IsObject()
  data: any;
}

export class SendFeaturedPropertyNotificationForAdmin {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  featuredProperty: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  body: string;

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  recipients: string[];

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  recipients_email: string[];

  @IsOptional()
  @IsEnum(NotificationPriority, { message: 'invalid priority type' })
  priority: NotificationPriority;

  @IsNotEmpty()
  @IsOptional()
  @IsObject()
  data: any;
}

export class SendBrokerRequestNotificationForAdmin {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  broker_request: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  body: string;

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  recipients: string[];

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  recipients_email: string[];

  @IsOptional()
  @IsEnum(NotificationPriority, { message: 'invalid priority type' })
  priority: NotificationPriority;

  @IsNotEmpty()
  @IsOptional()
  @IsObject()
  data: any;
}

export class SendPropertyReportNotificationForAdmin {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  report: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  body: string;

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  recipients: string[];

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  recipients_email: string[];

  @IsOptional()
  @IsEnum(NotificationPriority, { message: 'invalid priority type' })
  priority: NotificationPriority;

  @IsNotEmpty()
  @IsOptional()
  @IsObject()
  data: any;
}

export class SendListingPackagetNotificationForAdmin {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  broker_package: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  body: string;

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  recipients: string[];

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  recipients_email: string[];

  @IsOptional()
  @IsEnum(NotificationPriority, { message: 'invalid priority type' })
  priority: NotificationPriority;

  @IsNotEmpty()
  @IsOptional()
  @IsObject()
  data: any;
}
//========================user Notification=========================//

export class SendFeaturedPropertyNotificationForBroker {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  featuredProperty: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  body: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  user: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  recipient_email: string;

  @IsOptional()
  @IsEnum(NotificationPriority, { message: 'invalid priority type' })
  priority: NotificationPriority;

  @IsNotEmpty()
  @IsOptional()
  @IsObject()
  data: any;
}
export class SendAdsNotificationForBroker {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  ads: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  body: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  user: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  recipient_email: string;

  @IsOptional()
  @IsEnum(NotificationPriority, { message: 'invalid priority type' })
  priority: NotificationPriority;

  @IsNotEmpty()
  @IsOptional()
  @IsObject()
  data: any;
}

export class SendBrokerRequestNotificationForBroker {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  broker_request: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  body: string;

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  user: string;

  @IsNotEmpty()
  @IsOptional()
  @IsArray()
  recipient_email: string;

  @IsOptional()
  @IsEnum(NotificationPriority, { message: 'invalid priority type' })
  priority: NotificationPriority;

  @IsNotEmpty()
  @IsOptional()
  @IsObject()
  data: any;
}

export class SendListingPackagetNotificationForBroker {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  broker_package: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  body: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  user: string;
  @IsNotEmpty()
  @IsOptional()
  @IsString()
  recipient_email: string;

  @IsOptional()
  @IsEnum(NotificationPriority, { message: 'invalid priority type' })
  priority: NotificationPriority;

  @IsNotEmpty()
  @IsOptional()
  @IsObject()
  data: any;
}

export class SendPropertyReportNotificationForBroker {
  @IsNotEmpty()
  @IsString()
  @IsOptional()
  report: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  title: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  body: string;

  @IsNotEmpty()
  @IsOptional()
  @IsString()
  user: string;
  @IsNotEmpty()
  @IsOptional()
  @IsString()
  recipient_email: string;

  @IsOptional()
  @IsEnum(NotificationPriority, { message: 'invalid priority type' })
  priority: NotificationPriority;

  @IsNotEmpty()
  @IsOptional()
  @IsObject()
  data: any;
}
