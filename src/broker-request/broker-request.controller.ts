import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Param,
  ParseFilePipeBuilder,
  Post,
  Put,
  Query,
  UploadedFile,
  UseInterceptors,
  UseGuards,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  AcceptRequestDto,
  RejectRequestDto,
  SendRequestDto,
} from './dto/send-request.dto';
import { BrokerRequestService } from './broker-request.service';
import { SendBrokerRequestNotificationAndEmailInterceptor } from 'src/interceptors/notification.interceptors';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Role } from 'src/utils/role.enum';
import { Roles } from 'src/guards/role.decorator';

@Controller('broker-request')
export class BrokerRequestController {
  constructor(private brokerRequestService: BrokerRequestService) {}

  //make request
  @Post('new')
  @UseInterceptors(
    FileInterceptor('logo'),
    SendBrokerRequestNotificationAndEmailInterceptor,
  )
  async createNewRequest(
    @UploadedFile(
      new ParseFilePipeBuilder()
        // .addFileTypeValidator({
        //   fileType: /(jpg|jpeg|png|webp)$/,
        // })
        // .addMaxSizeValidator({
        //   maxSize: 10000,
        // })
        // .addValidator(
        //   new MaxFileSize({
        //     maxSize: 10000,
        //   }),
        // )
        .build({
          errorHttpStatusCode: HttpStatus.UNPROCESSABLE_ENTITY,
        }),
    )
    logo: Express.Multer.File,
    @Body() sendRequestDto: SendRequestDto,
  ) {
    return await this.brokerRequestService.sendRequest(sendRequestDto, logo);
  }

  // get all requests
  @Get('all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllRequestForAdmin(
    @Query('page') page = 1,
    @Query('perPage') perPage = 2,
  ) {
    return await this.brokerRequestService.getAllRequest(page, perPage);
  }

  //request detail
  @Get('detail/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async brokerRequestDetail(@Param('id') id: string) {
    return await this.brokerRequestService.brokerRequestDetail(id);
  }
  //accept broker request
  @Put('accept/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(SendBrokerRequestNotificationAndEmailInterceptor)
  async acceptBrokerRequest(
    @Param('id') id: string,
    @Body() data: AcceptRequestDto,
  ) {
    return await this.brokerRequestService.acceptBrokersRequest(data, id);
  }
  //reject broker request by admin
  @Put('reject/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  @UseInterceptors(SendBrokerRequestNotificationAndEmailInterceptor)
  async rejectBrokerRequest(
    @Param('id') id: string,
    @Body() data: RejectRequestDto,
  ) {
    return await this.brokerRequestService.rejectBrokersRequest(id, data);
  }
  //get own request status
  @Get('user/status/:id')
  async getOwnRequestInfo(@Param('id') id: string) {
    return await this.brokerRequestService.getOwnRequestInfo(id);
  }
}
