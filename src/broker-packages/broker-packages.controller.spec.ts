import { Test, TestingModule } from '@nestjs/testing';
import { BrokerPackagesController } from './broker-packages.controller';

describe('BrokerPackagesController', () => {
  let controller: BrokerPackagesController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [BrokerPackagesController],
    }).compile();

    controller = module.get<BrokerPackagesController>(BrokerPackagesController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
