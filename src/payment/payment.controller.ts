import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { PaymentService } from './payment.service';
import { MakePaymentDto } from './dto/payment.dto';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { RoleGuard } from 'src/guards/role.guard';
import { Role } from 'src/utils/role.enum';
import { Roles } from 'src/guards/role.decorator';

@Controller('payment')
export class PaymentController {
  constructor(private paymentService: PaymentService) {}
  @Post('create')
  async makePayment(@Body() data: MakePaymentDto) {
    return await this.paymentService.makePayment(data);
  }

  //get all payments for admin
  @Get('admin/all')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async getAllPaymentsForAdmin(
    @Query('page') page = 1,
    @Query('perPage') perPage = 2,
  ) {
    return this.paymentService.getAllPaymentsForAdmin(page, perPage);
  }

  //get payment analytics for admin
  @Get('admin/analytics')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Admin)
  async paymentAnalylicsForAdmin() {
    return this.paymentService.paymentAnalylicsForAdmin();
  }
  //==================brokers end point=================//
  @Get('broker/all/:id')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles(Role.Broker)
  async getAllPaymentsForBrokers(
    @Param('id') id: string, //broker id
    @Query('page') page = 1,
    @Query('perPage') perPage = 2,
  ) {
    return this.paymentService.getAllPaymentsForBrokers(page, perPage, id);
  }
}
