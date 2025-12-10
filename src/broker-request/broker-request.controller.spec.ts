import { Test, TestingModule } from '@nestjs/testing';
import { BrokerRequestController } from './broker-request.controller';

describe('BrokerRequestController', () => {
  let controller: BrokerRequestController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [BrokerRequestController],
    }).compile();

    controller = module.get<BrokerRequestController>(BrokerRequestController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
