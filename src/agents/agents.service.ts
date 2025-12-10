import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Agent } from './schema/agent.schema';
import { Model } from 'mongoose';
import { UsersService } from 'src/users/users.service';
import { CreateAgentDto } from './dto/create-agent.dto';
import { Role } from 'src/utils/role.enum';
import { PaginationService } from 'src/services/pagination.service';
import { hashedOtpOrPassword } from 'src/helpers/password.validator';
import { PropertyService } from 'src/property/property.service';

@Injectable()
export class AgentsService {
  constructor(
    private readonly paginationService: PaginationService,
    @InjectModel(Agent.name) private agentModel: Model<Agent>,
    private userService: UsersService,
    private propertyService: PropertyService,
  ) {}

  //create new agent service used by other module
  async createAgent(createAgentDto: { broker: any; user: any }) {
    return await this.agentModel.create(createAgentDto);
  }
  // for admin
  async getAgentsCount() {
    return await this.agentModel.countDocuments({ role: Role.Agent });
  }
  //get broker agents for brokers count
  async getBrokerAgentsCount(id: string) {
    return await this.agentModel.countDocuments({ broker: id });
  }

  //create agent by admin
  async createNewAgentByAdmin(createAgentDto: CreateAgentDto) {
    //check if the email and the phone is unique since the email work as login credential
    const user = await this.userService.findUserByEmail(createAgentDto.email);
    if (user && user.role === Role.Admin) {
      // check if the admin is also agent
      const isAgent = await this.agentModel.findOne({ user: user._id });
      if (isAgent) {
        throw new HttpException('You Are alrady Agent', HttpStatus.BAD_REQUEST);
      }
      const newAgent = await this.agentModel.create({
        broker: createAgentDto.broker ? createAgentDto.broker : null,
        user: user._id,
        isInHouseAgent: true,
        whatsappNumber: createAgentDto.whatsappNumber ?? null,
      });
      return newAgent;
    }
    //check if the phone is unique
    const isPhoneExist = await this.userService.findUserByPhone(
      createAgentDto.phone,
    );
    if (user) {
      throw new HttpException('Email Alrady Exist', HttpStatus.BAD_REQUEST);
    }
    if (isPhoneExist) {
      throw new HttpException('Phone Already Exist', HttpStatus.BAD_REQUEST);
    }
    // create new user that the user can login to the app to dashboard(based on his permission)
    const hashPassword = await hashedOtpOrPassword(createAgentDto.password);
    const newUser = await this.userService.createNewAgent({
      firstName: createAgentDto.firstName,
      lastName: createAgentDto.lastName,
      email: createAgentDto.email,
      phone: createAgentDto.phone,
      password: hashPassword,
      role: Role.Agent,
      permissions: createAgentDto.permissions,
    });
    const newAgent = await this.agentModel.create({
      broker: createAgentDto.broker ? createAgentDto.broker : null,
      user: newUser._id,
      isInHouseAgent: true,
      whatsappNumber: createAgentDto.whatsappNumber ?? null,
    });
    return newAgent;
  }
  // create agent by brokers
  async createNewAgent(createAgentDto: CreateAgentDto) {
    //check if the email and the phone is unique since the email work as login credential
    if (!createAgentDto.broker) {
      const user = await this.userService.findUserByEmail(createAgentDto.email);
      if (user && user.role !== Role.Admin) {
        throw new HttpException('Email  Already Exist', HttpStatus.BAD_REQUEST);
      }
      const newAgent = await this.agentModel.create({
        broker: createAgentDto.broker ? createAgentDto.broker : null,
        user: user._id,
        isInHouseAgent: true,
        whatsappNumber: createAgentDto.whatsappNumber ?? null,
      });
      return newAgent;
    }
    const user = await this.userService.findUserByEmail(createAgentDto.email);
    if (user) {
      throw new HttpException('Email  Already Exist', HttpStatus.BAD_REQUEST);
    }
    //check if the phone is unique
    const isPhoneExist = await this.userService.findUserByPhone(
      createAgentDto.phone,
    );
    if (isPhoneExist) {
      throw new HttpException('Phone Already Exist', HttpStatus.BAD_REQUEST);
    }
    // create new user that the user can login to the app to dashboard(based on his permission)
    const hashPassword = await hashedOtpOrPassword(createAgentDto.password);
    const newUser = await this.userService.createNewAgent({
      firstName: createAgentDto.firstName,
      lastName: createAgentDto.lastName,
      email: createAgentDto.email,
      phone: createAgentDto.phone,
      password: hashPassword,
      role: Role.Agent,
      permissions: createAgentDto.permissions,
    });
    //   create the agent now
    const newAgent = await this.agentModel.create({
      broker: createAgentDto.broker ? createAgentDto.broker : null,
      user: newUser._id,
      isInHouseAgent: createAgentDto.broker ? false : true,
      whatsappNumber: createAgentDto.whatsappNumber ?? null,
    });
    return newAgent;
  }

  //delete agent by admin
  async deleteInHouseAgentByAdmin(id: string) {
    const agent = await this.agentModel.findById(id);
    if (!agent) {
      throw new HttpException("Agent Doesn't Exist", HttpStatus.BAD_REQUEST);
    }
    // update the property agent to admin
    const adminAgent = await this.agentModel.findOne({
      isInHouseAgent: true,
      isAdmin: true,
    });
    await this.propertyService.updateMultiplePropertiesAgent(
      agent._id.toString(),
      adminAgent._id.toString(),
    );
    await this.agentModel.findByIdAndDelete(id);
    return 'agent deleted successfully';
  }

  //get all agents for admin (get in house agent) paginated
  async getAllInHouseAgent(page: number, perPage: number) {
    const allAgents = await this.agentModel
      .find({ broker: null, isInHouseAgent: true })
      .populate('user');
    const totalAgents = allAgents.length;
    const paginatedData = this.paginationService.paginate(
      allAgents,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalAgents,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalAgents,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
  // get unpaginated all in-house agents
  async getInHouseAgentsByAdmin() {
    return await this.agentModel
      .find({ isInHouseAgent: true, broker: null })
      .populate('user'); //add filter here
  }

  //delete agent
  async deleteAgent(id: string) {
    const isAgentExist = await this.agentModel.findById(id);
    if (!isAgentExist) {
      throw new HttpException("Agent Doesn't Exist", HttpStatus.BAD_REQUEST);
    }
    await this.agentModel.findByIdAndDelete(id);
    return 'agent deleted successfully';
  }
  /*******************BROKER RELATED API STARTS HERE **************************/
  async getAllMyAgent(page: number, perPage: number, id: string) {
    const allAgents = await this.agentModel
      .find({ broker: id })
      .populate('user');
    const totalAgents = allAgents.length;
    const paginatedData = this.paginationService.paginate(
      allAgents,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalAgents,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalAgents,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
  // get unpaginated all brokers agents
  async getCompanyAgents(id: string) {
    return await this.agentModel.find({ broker: id }).populate('user'); //add filter here
  }
}
