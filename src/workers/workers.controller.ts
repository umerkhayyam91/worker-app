import { Controller, Post, Body } from '@nestjs/common';
import { WorkersService } from './workers.service';
import {
  LoginDto,
  RequestPasswordResetDto,
  ResetPasswordDto,
  ForceLogoutDto,
  VerifyForceLogoutDto,
  SignupDto,
} from './dto/auth.dto';

@Controller('workers')
export class WorkersController {
  constructor(private readonly workersService: WorkersService) {}

  @Post('signup')
  async signup(@Body() signupDto: SignupDto) {
    return this.workersService.signup(signupDto);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.workersService.login(loginDto);
  }

  @Post('request-password-reset')
  async requestPasswordReset(@Body() dto: RequestPasswordResetDto) {
    return this.workersService.requestPasswordReset(dto);
  }

  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.workersService.resetPassword(dto);
  }

  @Post('request-force-logout')
  async requestForceLogout(@Body() dto: ForceLogoutDto) {
    return this.workersService.requestForceLogout(dto);
  }

  @Post('verify-force-logout')
  async verifyForceLogout(@Body() dto: VerifyForceLogoutDto) {
    return this.workersService.verifyForceLogout(dto);
  }
} 