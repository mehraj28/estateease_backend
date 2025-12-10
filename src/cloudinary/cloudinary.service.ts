// cloudinary.service.ts

import { Injectable } from '@nestjs/common';
import { v2 as cloudinary, UploadApiOptions } from 'cloudinary';
import { CloudinaryResponse } from './cloudinary-response';
import toStream = require('buffer-to-stream');
@Injectable()
export class CloudinaryService {
  uploadFile(file: Express.Multer.File): Promise<CloudinaryResponse> {
    return new Promise<CloudinaryResponse>((resolve, reject) => {
      const options: UploadApiOptions = {
        resource_type: 'auto', // Let Cloudinary detect the resource type (image or video)
      };

      cloudinary.uploader
        .upload_stream(options, (error, result) => {
          if (error) return reject(error);
          resolve(result);
        })
        .end(file.buffer);
    });
  }
  //upload multiple files images
  uploadFiles(files: Express.Multer.File[]): Promise<CloudinaryResponse[]> {
    const uploadPromises: Promise<CloudinaryResponse>[] = [];

    for (const file of files) {
      const uploadPromise = new Promise<CloudinaryResponse>(
        (resolve, reject) => {
          const uploadStream = cloudinary.uploader.upload_stream(
            (error, result) => {
              if (error) return reject(error);
              resolve(result);
            },
          );

          toStream(file.buffer).pipe(uploadStream);
        },
      );

      uploadPromises.push(uploadPromise);
    }

    return Promise.all(uploadPromises);
  }
}
