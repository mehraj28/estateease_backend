import { Test, TestingModule } from '@nestjs/testing';
import { BrokerRequestService } from './broker-request.service';

describe('BrokerRequestService', () => {
  let service: BrokerRequestService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [BrokerRequestService],
    }).compile();

    service = module.get<BrokerRequestService>(BrokerRequestService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
