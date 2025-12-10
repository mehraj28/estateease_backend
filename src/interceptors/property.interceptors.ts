import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { FeaturedPropertyService } from 'src/featured-property/featured-property.service';
import { PropertyService } from 'src/property/property.service';
@Injectable()
export class UpdateViewCountInterceptor implements NestInterceptor {
  constructor(
    private featuredPropertyService: FeaturedPropertyService,
    private propetyService: PropertyService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      tap((response) => {
        if (response && response.property) {
          console.log('called');
          // Perform the update operation in a separate event loop
          setImmediate(() => {
            // Update the view count of the property
            this.featuredPropertyService.updateViewCount(
              response.property?._id,
            );
            // update normal property view count
            this.propetyService.updateViewCount(response.property?._id);
          });
        }
      }),
    );
  }
}
