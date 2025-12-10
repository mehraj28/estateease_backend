import { Test, TestingModule } from '@nestjs/testing';
import { BrokerPackagesService } from './broker-packages.service';

describe('BrokerPackagesService', () => {
  let service: BrokerPackagesService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [BrokerPackagesService],
    }).compile();

    service = module.get<BrokerPackagesService>(BrokerPackagesService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
