import { Test, TestingModule } from '@nestjs/testing';
import { FeaturedPropertyController } from './featured-property.controller';

describe('FeaturedPropertyController', () => {
  let controller: FeaturedPropertyController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [FeaturedPropertyController],
    }).compile();

    controller = module.get<FeaturedPropertyController>(
      FeaturedPropertyController,
    );
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
