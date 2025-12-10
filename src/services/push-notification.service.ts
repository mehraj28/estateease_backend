// one-signal.service.ts
import * as OneSignal from 'onesignal-node';
import {
  SendNotificationDto,
  SendNotificationToAllDto,
} from './dto/send-notification.dto';

export class OneSignalPushNotificationService {
  private client: OneSignal.Client;

  constructor() {
    this.client = new OneSignal.Client(
      process.env.ONE_SIGNAL_APP_ID,
      process.env.ONE_SIGNAL_API_KEY,
    );
  }

  //send push notification to single user
  async pushNotificationToSingleUser(data: SendNotificationDto) {
    const notificationData = {
      contents: {
        tr: data.message,
        en: data.message,
      },
      include_player_ids: [data.deviceId],
      // included_segments: ['All'],
      large_icon: data.appIcon, // app logo
    };
    await this.client.createNotification(notificationData);
    return await this.client.viewDevices();
  }
  //send notifications to all users
  async pushNotificationToAllUsers(data: SendNotificationToAllDto) {
    const notificationData = {
      contents: {
        tr: data.message,
        en: data.message,
      },
      big_picture: data.bigPicture && data.bigPicture,
      included_segments: ['All'],
      small_icon: data.appIcon, // app logo
    };
    await this.client.createNotification(notificationData);
    return 'notification sent';
  }
  async sendPushNotification(message: string): Promise<void> {
    const data = {
      contents: {
        tr: 'Yeni bildirim',
        en: 'New notification',
      },
      big_picture:
        'https://res.cloudinary.com/dxrvoxbvu/image/upload/v1694791592/yqk8bqxdmcqgspeczypn.jpg',
      included_segments: ['All'],
      // filters: [{ field: 'tag', key: 'level', relation: '>', value: 10 }],
    };

    try {
      const notification = this.client.createNotification(data);
      //   const response = await this.client.sendNotification(notification);
      // console.log('Successfully sent notification:', notification);
    } catch (error) {
      console.error('Error sending notification:', error);
    }
  }
}
