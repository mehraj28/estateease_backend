import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Report } from './schema/report.schema';
import { Model } from 'mongoose';
import {
  HideReportPropertyDto,
  ReportPropertyDto,
} from './dto/report-property.dto';
import { PropertyService } from 'src/property/property.service';
import { UsersService } from 'src/users/users.service';
import {
  PropertyReporttAction,
  ReportPropertyAction,
} from 'src/utils/actions.enum';
import { PaginationService } from 'src/services/pagination.service';

@Injectable()
export class ReportService {
  constructor(
    @InjectModel(Report.name) private reportModel: Model<Report>,
    private readonly propertyService: PropertyService,
    private readonly userService: UsersService,
    private readonly paginationService: PaginationService,
  ) {}

  //report a property by user
  async reportProperty(data: ReportPropertyDto) {
    //check if the user previously report the property or not
    // first if user is exist or not
    const isUserExist = await this.userService.findUserById(data.user);
    if (!isUserExist) {
      throw new HttpException('user not found', HttpStatus.NOT_FOUND);
    }
    // check if the property is exist or not
    const isPropertyExist = await this.propertyService.findPropertyById(
      data.property,
    );
    if (!isPropertyExist) {
      throw new HttpException('Property not found', HttpStatus.NOT_FOUND);
    }
    const report = await this.reportModel.create({
      user: data.user,
      property: data.property,
      discription: data.discription,
    });
    (await report.populate('property')).populate('user');
    return {
      data: report,
      property: isPropertyExist,
      type: PropertyReporttAction.CREATE,
    };
  }

  //---------------admin--end point---------------------------//
  async getAllReportedPropertiesForAdmin(
    page: number,
    perPage: number,
    type: ReportPropertyAction,
  ) {
    const { reportModel, paginationService } = this; // Destructure for readability

    // Create a common query object
    let commonQuery = {};

    // Add type-specific conditions
    if (type === ReportPropertyAction.NEW) {
      commonQuery['status'] = ReportPropertyAction.NEW;
    } else if (type === ReportPropertyAction.PENDING) {
      commonQuery['status'] = ReportPropertyAction.PENDING;
    } else if (type === ReportPropertyAction.CORRECTED) {
      commonQuery['status'] = ReportPropertyAction.CORRECTED;
    } else if (type === ReportPropertyAction.ALL) {
      commonQuery = {};
    }
    // Use Promise.all to parallelize multiple async calls
    const [allReportedProperties, totalProperties] = await Promise.all([
      reportModel
        .find(commonQuery)
        .populate('property')
        .populate('user')
        .populate({
          path: 'property',
          populate: {
            path: 'broker', // Populate the 'broker' field within 'property'
          },
        }),
      reportModel.countDocuments(commonQuery),
    ]);

    const paginatedData = paginationService.paginate(
      allReportedProperties,
      page,
      perPage,
    );

    const totalPages = paginationService.calculateTotalPages(
      totalProperties,
      perPage,
    );

    return {
      pagination: {
        data: paginatedData,
        page,
        perPage,
        totalProperties,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
    };
  }
  //reportd detail
  async reportedPropertyDetail(id: string) {
    const singleReport = await this.reportModel.findById(id);
    const report = await this.reportModel
      .findById(id)
      .populate('property')
      .populate('user')
      .populate({
        path: 'property',
        populate: {
          path: 'broker', // Populate the 'broker' field within 'property'
        },
      })
      .populate({
        path: 'property',
        populate: {
          path: 'owner', // Populate the 'owner' field within 'property'
        },
      });
    // get also related reports on this property
    const relatedReport = await this.reportModel
      .find({
        property: singleReport.property,
        _id: { $ne: id },
      })
      .populate('property')
      .populate('user')
      .populate({
        path: 'property',
        populate: {
          path: 'broker', // Populate the 'broker' field within 'property'
        },
      });
    // udate the status of the report
    await this.reportModel.findByIdAndUpdate(
      id,
      { $set: { status: ReportPropertyAction.VIEWED } },
      { new: true },
    );
    if (!report) {
      throw new HttpException('No report is found', HttpStatus.BAD_REQUEST);
    }
    return { report, relatedReport };
  }

  //hide the property by admin
  async temporaryHideThePropertyByAdmin(
    id: string,
    data: HideReportPropertyDto,
  ) {
    // first if user is exist or not
    const report = await this.reportModel.findById(id);
    if (!report) {
      throw new HttpException('user not found', HttpStatus.NOT_FOUND);
    }
    //hidde the property
    const hideProperty = await this.reportModel
      .findByIdAndUpdate(
        id,
        { $set: { status: ReportPropertyAction.PENDING } },
        { new: true },
      )
      .populate('property');

    await this.propertyService.hidePropertyFromUserByAdin(
      report.property.toString(),
    );
    return {
      data: hideProperty,
      message: data.message,
      type: ReportPropertyAction.PENDING,
    };
  }

  //make the reporeted property visible previosly hidden due to report
  async makeThePropertyVisibleThePropertyByAdmin(id: string) {
    // first if user is exist or not
    const report = await this.reportModel.findById(id);
    if (!report) {
      throw new HttpException('user not found', HttpStatus.NOT_FOUND);
    }
    //hidde the property
    const hideProperty = await this.reportModel
      .findByIdAndUpdate(
        id,
        { $set: { status: ReportPropertyAction.APPROVED } },
        { new: true },
      )
      .populate('property');

    await this.propertyService.makeHiddenPropertyVisibleByAdmin(
      report.property.toString(),
    );
    return {
      data: hideProperty,
      type: ReportPropertyAction.APPROVED,
    };
  }

  //=================request for approval to admin by broker to activate the property==============//
  //make the reporeted property visible previosly hidden due to report
  async makeRequestForApproveToAdmin(id: string) {
    // first if user is exist or not
    const report = await this.reportModel.findById(id);
    if (!report) {
      throw new HttpException('user not found', HttpStatus.NOT_FOUND);
    }
    //hidde the property
    const hideProperty = await this.reportModel
      .findByIdAndUpdate(
        id,
        { $set: { status: ReportPropertyAction.CORRECTED } },
        { new: true },
      )
      .populate('property');

    return {
      data: hideProperty,
      type: ReportPropertyAction.CORRECTED,
    };
  }
}
