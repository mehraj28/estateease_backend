import {
  Injectable,
  PipeTransform,
  HttpStatus,
  ArgumentMetadata,
} from '@nestjs/common';
import { ValidationPipe } from '@nestjs/common';
import { CloudinaryService } from '../cloudinary/cloudinary.service';

@Injectable()
export class CloudinaryValidationPipe implements PipeTransform {
  constructor(
    private readonly cloudinaryService: CloudinaryService,
    private readonly fieldName: string,
  ) {}

  async transform(value: any, metadata: ArgumentMetadata) {
    const logo = value[this.fieldName];

    // Call the Cloudinary service to upload the logo and get the image URL
    const imageUrl = await this.cloudinaryService.uploadFile(logo);
    // Set the image URL in the DTO
    value[this.fieldName] = imageUrl;

    // Create a new instance of the ValidationPipe
    const validationPipe = new ValidationPipe({
      transform: true,
      errorHttpStatusCode: HttpStatus.UNPROCESSABLE_ENTITY,
    });

    // Apply the ValidationPipe to validate the transformed value
    return validationPipe.transform(value, metadata);
  }
}
