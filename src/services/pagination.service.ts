import { Injectable } from '@nestjs/common';

@Injectable()
export class PaginationService {
  paginate(data: any[], page = 1, perPage = 10): any[] {
    const startIndex = (page - 1) * perPage;
    const endIndex = startIndex + perPage;
    const paginatedData = data.slice(startIndex, endIndex);

    return paginatedData;
  }

  calculateTotalPages(totalItems: number, perPage: number): number {
    return Math.ceil(totalItems / perPage);
  }
}
