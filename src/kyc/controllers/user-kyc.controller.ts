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
} from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/auth.guard';
import { UserKycService } from '../services/user-kyc.service';
import { GetAllUserKycDto } from '../dto/user-kyc-get-all.dto';
import { AuthActor } from '../../common/types/auth.type';
import type { Request } from 'express';
import { VerifyUserKycDto } from '../dto/user-kyc-verify.dto';

@Controller('api/v1/user-kyc')
@UseGuards(JwtAuthGuard)
export class UserKYCController {
  constructor(private readonly userKYCService: UserKycService) {}

  // ------------------- GET ALL by user, employee and root -------------------
  @Get('get-all')
  findAll(@Req() req: Request, @Query() query: GetAllUserKycDto) {
    const currentUser = req.user as AuthActor;
    return this.userKYCService.getAll(query, currentUser);
  }

  // ------------------- GET BY ID by user, employee and root -------------------
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.userKYCService.getById(id);
  }

  // ------------------- DELETE by user, employee and root -------------------
  @Delete(':id')
  remove(@Req() req: Request, @Param('id') id: string) {
    const currentUser = req.user as AuthActor;
    return this.userKYCService.delete(id, currentUser);
  }

  // ------------------- VERIFY by user, employee and root -------------------
  @Patch(':id')
  verify(
    @Req() req: Request,
    @Param('id') id: string,
    @Body() dto: VerifyUserKycDto,
  ) {
    const currentUser = req.user as AuthActor;
    return this.userKYCService.verify(id, dto, currentUser);
  }
}
