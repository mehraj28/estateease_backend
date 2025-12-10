import {
  Catch,
  ExceptionFilter,
  ArgumentsHost,
  HttpException,
} from '@nestjs/common';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    const request = ctx.getRequest();
    const status = exception.getStatus();

    let message: any = exception.getResponse();
    if (typeof message === 'object' && message.message) {
      message = message.message;
    }

    response.status(status).json({
      statusCode: status,
      message: message || 'Something went wrong',
      timestamp: new Date().toISOString(),
      path: request.url,
    });
  }
}
