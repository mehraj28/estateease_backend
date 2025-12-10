import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { AgentsService } from './agents.service';
import { CreateAgentDto } from './dto/create-agent.dto';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Roles } from 'src/guards/role.decorator';
import { Role } from 'src/utils/role.enum';

@Controller('agents')
export class AgentsController {
  constructor(private agentService: AgentsService) {}

  //create agent by admin or broker
  @Post('create/admin')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin, Role.Broker)
  async createNewAgentByAdmin(@Body() createAgentDto: CreateAgentDto) {
    await this.agentService.createNewAgentByAdmin(createAgentDto);
  }

  @Post('create')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin, Role.Broker)
  async createNewAgent(@Body() createAgentDto: CreateAgentDto) {
    await this.agentService.createNewAgent(createAgentDto);
  }

  //get all in house agents by admin getInHouseAgentsByAdmin
  @Get('admin/in-house-agents')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllInHouseAgents(
    @Query('page') page = 1,
    @Query('perPage') perPage = 2,
  ) {
    return await this.agentService.getAllInHouseAgent(page, perPage);
  }

  @Get('admin/in-house-agents/all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getInHouseAgentsByAdmin() {
    return await this.agentService.getInHouseAgentsByAdmin();
  }

  //delete inhouse agent
  @Delete('find/admin/delete/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async deleteInHouseAgentByAdmin(@Param('id') id: string) {
    return this.agentService.deleteInHouseAgentByAdmin(id);
  }
  //delete agent
  @Delete('find/delete/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker)
  async deleteAgent(@Param('id') id: string) {
    return this.agentService.deleteAgent(id);
  }

  /*******************BROKER RELATED API STARTS HERE **************************/
  @Get('broker/agents/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker)
  async getAllMyAgent(
    @Query('page') page = 1,
    @Query('perPage') perPage = 2,
    @Param('id') id: string,
  ) {
    return await this.agentService.getAllMyAgent(page, perPage, id);
  }
  //get unpaginated company agents
  @Get('broker/all/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker, Role.Admin)
  async getCompanyAgents(@Param('id') id: string) {
    return await this.agentService.getCompanyAgents(id);
  }
}
