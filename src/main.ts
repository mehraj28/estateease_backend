import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { TrimPipe } from './pipes/trim-data.pipe';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Global API prefix
  app.setGlobalPrefix('api');

  // Global pipes
  app.useGlobalPipes(new TrimPipe());
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // ✅ CORS FIX (Netlify + Render + Localhost)
  app.enableCors({
    origin: [
      'https://estateeaseadmin.netlify.app',
      'http://localhost:3000',
      'http://localhost:4200',
    ],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: 'Content-Type, Authorization',
    credentials: false,
  });

  // Server listen
  const port = process.env.PORT || 5000;
  await app.listen(port);

  console.log(`✅ Server running on port ${port}`);
}

bootstrap();
