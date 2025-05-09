import { IsString, IsEmail, IsPhoneNumber, MinLength, IsOptional } from 'class-validator';

export class SignupDto {
  @IsEmail()
  email: string;

  @IsPhoneNumber()
  phoneNumber: string;

  @IsString()
  @MinLength(6)
  password: string;
}

export class LoginDto {
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsPhoneNumber()
  phoneNumber?: string;

  @IsString()
  @MinLength(6)
  password: string;
}

export class RequestPasswordResetDto {
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsPhoneNumber()
  phoneNumber?: string;
}

export class ResetPasswordDto {
  @IsString()
  otp: string;

  @IsString()
  @MinLength(6)
  newPassword: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsPhoneNumber()
  phoneNumber?: string;
}

export class ForceLogoutDto {
  @IsPhoneNumber()
  phoneNumber: string;
}

export class VerifyForceLogoutDto {
  @IsPhoneNumber()
  phoneNumber: string;

  @IsString()
  otp: string;
} 