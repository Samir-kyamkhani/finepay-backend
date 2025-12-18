import {
  IsOptional,
  IsString,
  IsObject,
  IsEmail,
  IsUrl,
} from 'class-validator';

export class UpsertSystemSettingDto {
  // ================= BASIC =================
  @IsOptional()
  @IsString()
  companyName?: string;

  @IsOptional()
  @IsString()
  companyLogo?: string;

  @IsOptional()
  @IsString()
  favIcon?: string;

  // ================= CONTACT =================
  @IsOptional()
  @IsString()
  phoneNumber?: string;

  @IsOptional()
  @IsString()
  whatsappNumber?: string;

  @IsOptional()
  @IsEmail()
  companyEmail?: string;

  // ================= SOCIAL LINKS =================
  @IsOptional()
  @IsUrl()
  facebookUrl?: string;

  @IsOptional()
  @IsUrl()
  instagramUrl?: string;

  @IsOptional()
  @IsUrl()
  twitterUrl?: string;

  @IsOptional()
  @IsUrl()
  linkedinUrl?: string;

  @IsOptional()
  @IsUrl()
  websiteUrl?: string;

  // ================= ADVANCED =================
  @IsOptional()
  @IsObject()
  settings?: Record<string, any>;
}
