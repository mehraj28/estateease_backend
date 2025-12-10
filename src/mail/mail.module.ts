import { Global, Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { MailController } from './mail.controller';
import { ConfigService } from '@nestjs/config';
import { MailerModule } from '@nestjs-modules/mailer';
import { EjsAdapter } from '@nestjs-modules/mailer/dist/adapters/ejs.adapter';
import { join } from 'path';
@Module({
  imports: [
    MailerModule.forRootAsync({
      useFactory: async (config: ConfigService) => ({
        transport: {
          // host: config.get('MAIL_HOST'),
          service: 'Mailjet',
          secure: false,
          auth: {
            user: process.env.MAILJET_API_KEY, // Replace with your Mailjet API key process.env.EMAIL_SENDER
            pass: process.env.MAILJET_API_SECRET, // Replace with your Mailjet API secret
          },
        },
        defaults: {
          from: `"Nice App" <${config.get('EMAIL_SENDER')}>`,
        },
        template: {
          dir: join(__dirname, 'templates'),
          adapter: new EjsAdapter(),
          options: {
            strict: false,
          },
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [MailService],
  controllers: [MailController],
})
export class MailModule {}
