import { Module } from '@nestjs/common';
import { AgentsController } from './agents.controller';
import { AgentsService } from './agents.service';
import { UsersModule } from 'src/users/users.module';
import { MongooseModule } from '@nestjs/mongoose';
import { Agent, AgentSchema } from './schema/agent.schema';
import { PaginationService } from 'src/services/pagination.service';
import { PropertyModule } from 'src/property/property.module';

@Module({
  imports: [
    UsersModule,
    MongooseModule.forFeature([{ name: Agent.name, schema: AgentSchema }]),
    PropertyModule,
  ],
  controllers: [AgentsController],
  providers: [AgentsService, PaginationService],
  exports: [AgentsService],
})
export class AgentsModule {}
