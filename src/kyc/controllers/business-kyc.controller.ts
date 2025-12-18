import {
  Controller,
  Get,
  Patch,
  Param,
  Delete,
  UseGuards,
  Req,
  Query,
  Body,
  ParseUUIDPipe,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/auth.guard';
import { BusinessKycService } from '../services/business-kyc.service';
import { BusinessKycQueryDto } from '../dto/business-kyc-query.dto';
import { AuthActor } from '../../common/types/auth.type';
import { VerifyBusinessKycDto } from '../dto/business-kyc-verify.dto';
import type { Request } from 'express';

@Controller('api/v1/business-kyc')
@UseGuards(JwtAuthGuard)
export class BusinessKYCController {
  constructor(private readonly businessKYCService: BusinessKycService) {}

  // ------------------- GET ALL by user, employee and root  -------------------
  @Get('get-all')
  findAll(@Req() req: Request, @Query() query: BusinessKycQueryDto) {
    const currentUser = req.user as AuthActor;
    return this.businessKYCService.getAll(query, currentUser);
  }

  // ------------------- GET BY ID by user, employee and root -------------------
  @Get(':id')
  findOne(@Param('id', ParseUUIDPipe) id: string) {
    return this.businessKYCService.getById(id);
  }

  // ------------------- DELETE by employee and root-------------------
  @Delete(':id')
  remove(@Req() req: Request, @Param('id') id: string) {
    const currentUser = req.user as AuthActor;
    return this.businessKYCService.delete(id, currentUser);
  }

  // ------------------- VERIFY by employee and root -------------------
  @Patch(':id')
  verify(
    @Req() req: Request,
    @Param('id') id: string,
    @Body() dto: VerifyBusinessKycDto,
  ) {
    const currentUser = req.user as AuthActor;
    return this.businessKYCService.verify(id, dto, currentUser);
  }
}
