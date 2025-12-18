import {
  Body,
  Controller,
  Delete,
  Get,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { Request } from 'express';
import { JwtAuthGuard } from '../common/guards/auth.guard';
import { SmtpConfigService } from './smtp-config.service';
import { CreateSmtpConfigDto } from './dto/create-smtp-config.dto';
import { UpdateSmtpConfigDto } from './dto/update-smtp-config.dto';
import { TestSmtpDto } from './dto/test-smtp-config.dto';
import { AuthActor } from '../common/types/auth.type';

@Controller('smtp')
@UseGuards(JwtAuthGuard)
export class SmtpController {
  constructor(private readonly smtpService: SmtpConfigService) {}

  // ================= CREATE =================
  @Post()
  create(@Req() req: Request, @Body() dto: CreateSmtpConfigDto) {
    const currentUser = req.user as AuthActor;
    return this.smtpService.create(currentUser, dto);
  }

  // ================= UPDATE =================
  @Put()
  update(@Req() req: Request, @Body() dto: UpdateSmtpConfigDto) {
    const currentUser = req.user as AuthActor;
    return this.smtpService.update(currentUser.id, dto);
  }

  // ================= DELETE =================
  @Delete()
  remove(@Req() req: Request) {
    const currentUser = req.user as AuthActor;
    return this.smtpService.remove(currentUser.id);
  }

  // ================= GET MY SMTP =================
  @Get('me')
  getMySmtp(@Req() req: Request) {
    const currentUser = req.user as AuthActor;
    return this.smtpService.getByUserId(currentUser.id);
  }

  // ================= GET ALL (ADMIN / ROOT) =================
  @Get()
  getAll() {
    return this.smtpService.getAll();
  }

  // ================= TEST SMTP =================
  @Post('test')
  test(@Req() req: Request, @Body() dto: TestSmtpDto) {
    const currentUser = req.user as AuthActor;
    return this.smtpService.testSmtp(currentUser, dto.testEmail);
  }
}
