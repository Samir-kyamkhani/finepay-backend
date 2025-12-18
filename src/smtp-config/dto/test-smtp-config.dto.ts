import { IsEmail } from 'class-validator';

export class TestSmtpDto {
  @IsEmail()
  testEmail: string;
}
