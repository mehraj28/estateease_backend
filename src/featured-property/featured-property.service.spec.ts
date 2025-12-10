import { Test, TestingModule } from '@nestjs/testing';
import { FeaturedPropertyService } from './featured-property.service';

describe('FeaturedPropertyService', () => {
  let service: FeaturedPropertyService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [FeaturedPropertyService],
    }).compile();

    service = module.get<FeaturedPropertyService>(FeaturedPropertyService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
