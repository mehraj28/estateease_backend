import { FileValidator } from '@nestjs/common';

export class MaxFileSize extends FileValidator<{ maxSize: number }> {
  constructor(options: { maxSize: number }) {
    super(options);
  }
  isValid(file?: any): boolean | Promise<boolean> {
    if (!file) {
      return false;
    }
    const in_mb = file.size / 1000;
    return in_mb <= this.validationOptions.maxSize;
  }

  buildErrorMessage(): string {
    return `File uploaded is too big. Max size is (${this.validationOptions.maxSize} MB)`;
  }
}
