import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as paypal from '@paypal/checkout-server-sdk';
import { Payment } from './schema/payment.schema';
import mongoose, { Model } from 'mongoose';
import { PaginationService } from 'src/services/pagination.service';
import { isValidMongooseId } from 'src/helpers/id-validator';
import { MakePaymentDto } from './dto/payment.dto';
import { RequestFeaturedPropertyDto } from 'src/featured-property/dto/featured-property.dto';
import { CreateAdsDto } from 'src/ads/dto/create-ads.dt';
import { PaymentStatus } from 'src/utils/status.enum';
import { CreateBrokerPackageDto } from 'src/broker-packages/dto/create-broker-package.dto';

@Injectable()
export class PaymentService {
  constructor(
    @InjectModel(Payment.name) private paymentModel: Model<Payment>,
    private paginationService: PaginationService,
  ) {}
  //total mony got from ads anf listing package at all
  async totalMoneyGot() {
    return this.paymentModel.aggregate([
      {
        $match: {
          status: PaymentStatus.APPROVED,
        },
      },
      {
        $addFields: {
          amountAsNumber: { $toDouble: '$amount' }, // Convert the 'amount' field to a number
        },
      },
      {
        $group: {
          _id: null,
          totalAmount: { $sum: '$amountAsNumber' }, // Calculate the sum of the converted 'amountAsNumber' field
        },
      },
    ]);
  }
  //total mone spend of broker used by other services
  async totalMoneySpentOfBroker(id: string) {
    return this.paymentModel.aggregate([
      {
        $match: {
          broker: new mongoose.Types.ObjectId(id),
          status: PaymentStatus.APPROVED,
        },
      },
      {
        $addFields: {
          amountAsNumber: { $toDouble: '$amount' }, // Convert the 'amount' field to a number
        },
      },
      {
        $group: {
          _id: null,
          totalAmount: { $sum: '$amountAsNumber' }, // Calculate the sum of the converted 'amountAsNumber' field
        },
      },
    ]);
  }
  //make payment for package listing
  async makePayment(data: MakePaymentDto) {
    const environment = new paypal.core.SandboxEnvironment(
      process.env.PAYPAL_CLIENT_ID,
      process.env.PAYPAL_CLIENT_SECRET,
    );
    const client = new paypal.core.PayPalHttpClient(environment);

    // Use the order ID from the frontend to get the order
    const orderRequest = new paypal.orders.OrdersGetRequest(data.paymentId);

    try {
      const orderResponse = await client.execute(orderRequest);
      const order = orderResponse.result;
      // console.log('Order retrieved successfully:', order);

      // Record the transaction details in your database
      const payment = await this.paymentModel.create(data);

      return payment;
    } catch (error) {
      console.log('err', error);
    }
  }
  async makePaymentForFeaturedProperty(data: RequestFeaturedPropertyDto) {
    const environment = new paypal.core.SandboxEnvironment(
      process.env.PAYPAL_CLIENT_ID,
      process.env.PAYPAL_CLIENT_SECRET,
    );
    const client = new paypal.core.PayPalHttpClient(environment);

    // Use the order ID from the frontend to get the order
    const orderRequest = new paypal.orders.OrdersGetRequest(data.paymentId);

    try {
      const orderResponse = await client.execute(orderRequest);
      const order = orderResponse.result;
      // console.log('Order retrieved successfully:', order);

      // Record the transaction details in your database
      const payment = await this.paymentModel.create(data);

      return payment;
    } catch (error) {
      console.log('err', error);
    }
  }
  async makePaymentForAdsBanner(data: CreateAdsDto) {
    const environment = new paypal.core.SandboxEnvironment(
      process.env.PAYPAL_CLIENT_ID,
      process.env.PAYPAL_CLIENT_SECRET,
    );
    const client = new paypal.core.PayPalHttpClient(environment);

    // Use the order ID from the frontend to get the order
    const orderRequest = new paypal.orders.OrdersGetRequest(data.paymentId);

    try {
      const orderResponse = await client.execute(orderRequest);
      const order = orderResponse.result;
      // console.log('Order retrieved successfully:', order);

      // Record the transaction details in your database
      const payment = await this.paymentModel.create(data);

      return payment._id;
    } catch (error) {
      console.log('err', error);
    }
  }

  //make payment for listing package
  async makePaymentForListingPackage(data: CreateBrokerPackageDto) {
    const environment = new paypal.core.SandboxEnvironment(
      process.env.PAYPAL_CLIENT_ID,
      process.env.PAYPAL_CLIENT_SECRET,
    );
    const client = new paypal.core.PayPalHttpClient(environment);

    // Use the order ID from the frontend to get the order
    const orderRequest = new paypal.orders.OrdersGetRequest(data.paymentId);

    try {
      const orderResponse = await client.execute(orderRequest);
      const order = orderResponse.result;
      // console.log('Order retrieved successfully:', order);

      // Record the transaction details in your database
      const payment = await this.paymentModel.create(data);

      return payment._id;
    } catch (error) {
      console.log('err', error);
    }
  }
  //receive all payments for admin
  async getAllPaymentsForAdmin(page: number, perPage: number) {
    const allPayments = await this.paymentModel.find({}).populate('broker');
    const totalPayments = allPayments.length;
    const paginatedData = this.paginationService.paginate(
      allPayments,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalPayments,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalPayments,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }

  //get payment detail
  async getPaymentDetail(id: string) {
    const isValidId = await isValidMongooseId(id);
    if (!isValidId) {
      throw new HttpException('Invalid Id', HttpStatus.BAD_REQUEST);
    }
    const payment = await this.paymentModel.findById(id);
    return payment;
  }

  //approve payment
  async approvePayment(id: string) {
    const isValidId = await isValidMongooseId(id);
    if (!isValidId) {
      throw new HttpException('Invalid Id', HttpStatus.BAD_REQUEST);
    }
    const payment = await this.paymentModel.findById(id);
    if (!payment) {
      throw new HttpException('Payment Does Not Exist', HttpStatus.BAD_REQUEST);
    }
    const approvePayment = await this.paymentModel.findByIdAndUpdate(
      id,
      {
        $set: {
          status: PaymentStatus.APPROVED,
        },
      },
      { new: true },
    );
    return approvePayment;
  }

  //get payment analytics for admin panel
  async paymentAnalylicsForAdmin() {
    const currentDate = new Date();
    const currentYear = currentDate.getFullYear();
    const currentMonth = currentDate.getMonth() + 1;

    const startMonth = currentMonth;
    const startYear = currentYear - 1;

    const monthYearPairs = [];
    for (let year = startYear; year <= currentYear; year++) {
      const endMonth = year === currentYear ? currentMonth : 12; // Include current month if it's the current year
      for (let month = 1; month <= endMonth; month++) {
        if (year === startYear && month < startMonth) {
          continue;
        }
        monthYearPairs.push({ year, month });
      }
    }

    const result = await this.paymentModel.aggregate([
      {
        $group: {
          _id: {
            year: { $year: '$timestamp' },
            month: { $month: '$timestamp' },
          },
          totalAmount: {
            $sum: {
              $cond: [{ $ifNull: ['$amount', 0] }, { $toDouble: '$amount' }, 0],
            },
          },
        },
      },
      {
        $project: {
          _id: 0, // Exclude _id field
          monthYear: {
            $dateToString: {
              format: '%Y-%m', // Format as 'YYYY-MM'
              date: {
                $dateFromParts: {
                  year: '$_id.year',
                  month: '$_id.month',
                  day: 1, // Assuming day as 1, you can adjust as needed
                },
              },
            },
          },
          totalAmount: 1,
        },
      },
      {
        $sort: { monthYear: 1 },
      },
    ]);
    // Create an array with 12 items, initializing each month's total to 0
    const monthlyTotals = monthYearPairs.map(({ year, month }) => {
      const monthString = `${year}-${month.toString().padStart(2, '0')}`;
      const matchingItem = result.find(
        (item) => item.monthYear === monthString,
      );
      return {
        month: monthString + '-10',
        totalAmount: matchingItem ? matchingItem.totalAmount : 0,
      };
    });

    return monthlyTotals;
  }
  //==================brokers and agents api =============//
  async getAllPaymentsForBrokers(page: number, perPage: number, id: string) {
    const allPayments = await this.paymentModel
      .find({ broker: id })
      .populate('user');
    const totalPayments = allPayments.length;
    const paginatedData = this.paginationService.paginate(
      allPayments,
      page,
      perPage,
    );
    const totalPages = this.paginationService.calculateTotalPages(
      totalPayments,
      perPage,
    );
    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalPayments,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
}
