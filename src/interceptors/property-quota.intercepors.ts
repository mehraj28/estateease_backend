import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { BrokerPackagesService } from 'src/broker-packages/broker-packages.service';

@Injectable()
export class SubstractListigPackageOfBroker implements NestInterceptor {
  constructor(private brokerPackageService: BrokerPackagesService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      tap((response) => {
        if (response) {
          // Perform the update operation in a separate event loop
          setImmediate(() => {
            // Update the listing quota package of the broker
            this.brokerPackageService.substractListingQuota(response.broker);
          });
        }
      }),
    );
  }
}
