import { Injectable, UnauthorizedException, BadRequestException, ConflictException, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Worker, WorkerDocument } from './schemas/worker.schema';
import { LoginDto, RequestPasswordResetDto, ResetPasswordDto, ForceLogoutDto, VerifyForceLogoutDto, SignupDto } from './dto/auth.dto';
import { NotificationsService } from '../notifications/notifications.service';

@Injectable()
export class WorkersService {
  private readonly logger = new Logger(WorkersService.name);

  constructor(
    @InjectModel(Worker.name) private workerModel: Model<WorkerDocument>,
    private jwtService: JwtService,
    private notificationsService: NotificationsService,
  ) {}

  async signup(signupDto: SignupDto) {
    const { email, phone, password } = signupDto;
    this.logger.debug(`Attempting to signup user with email: ${email} and phone: ${phone}`);

    // Check if user already exists
    const existingWorker = await this.workerModel.findOne({
      $or: [{ email }, { phoneNumber: phone }],
    });

    if (existingWorker) {
      this.logger.debug(`User already exists with email: ${existingWorker.email} or phone: ${existingWorker.phoneNumber}`);
      throw new ConflictException('User with this email or phone number already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new worker
    const worker = await this.workerModel.create({
      email,
      phoneNumber: phone,
      password: hashedPassword,
      activeSessions: [],
    });

    this.logger.debug(`Successfully created user with id: ${worker._id}`);

    // Generate JWT token
    const token = this.jwtService.sign({ sub: worker._id });
    worker.activeSessions.push(token);
    await worker.save();

    return {
      message: 'User registered successfully',
      token,
    };
  }

  async login(loginDto: LoginDto) {
    const { email, phoneNumber, password } = loginDto;
    
    if (!email && !phoneNumber) {
      throw new BadRequestException('Either email or phone number is required');
    }

    const worker = await this.workerModel.findOne({
      ...(email ? { email } : { phoneNumber }),
    });

    if (!worker || !(await bcrypt.compare(password, worker.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const token = this.jwtService.sign({ sub: worker._id });
    worker.activeSessions.push(token);
    await worker.save();

    return { token };
  }

  async requestPasswordReset(dto: RequestPasswordResetDto) {
    const { email, phoneNumber } = dto;
    
    if (!email && !phoneNumber) {
      throw new BadRequestException('Either email or phone number is required');
    }

    const worker = await this.workerModel.findOne({
      ...(email ? { email } : { phoneNumber }),
    });

    if (!worker) {
      throw new BadRequestException('Worker not found');
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    worker.resetPasswordOtp = await bcrypt.hash(otp, 10);
    worker.resetPasswordOtpExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    await worker.save();

    if (email) {
      await this.notificationsService.sendEmailOtp(email, otp);
    } else if (phoneNumber) {
      await this.notificationsService.sendSmsOtp(phoneNumber, otp);
    }

    return { message: 'OTP sent successfully' };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const { otp, newPassword, email, phoneNumber } = dto;
    
    if (!email && !phoneNumber) {
      throw new BadRequestException('Either email or phone number is required');
    }

    if (!otp) {
      throw new BadRequestException('OTP is required');
    }

    if (!newPassword) {
      throw new BadRequestException('New password is required');
    }

    const worker = await this.workerModel.findOne({
      ...(email ? { email } : { phoneNumber }),
    });

    if (!worker) {
      throw new BadRequestException('User not found');
    }

    if (!worker.resetPasswordOtp) {
      throw new BadRequestException('No password reset request found. Please request a password reset first.');
    }

    if (!worker.resetPasswordOtpExpiry) {
      throw new BadRequestException('Password reset request has expired. Please request a new one.');
    }

    if (worker.resetPasswordOtpExpiry < new Date()) {
      throw new BadRequestException('Password reset request has expired. Please request a new one.');
    }

    const isOtpValid = await bcrypt.compare(otp, worker.resetPasswordOtp);
    if (!isOtpValid) {
      throw new UnauthorizedException('Invalid OTP');
    }

    // Hash and update the new password
    worker.password = await bcrypt.hash(newPassword, 10);
    
    // Clear OTP fields
    worker.resetPasswordOtp = undefined;
    worker.resetPasswordOtpExpiry = undefined;
    
    // Clear all active sessions
    worker.activeSessions = [];
    
    await worker.save();

    return { message: 'Password reset successful' };
  }

  async requestForceLogout(dto: ForceLogoutDto) {
    const worker = await this.workerModel.findOne({ phoneNumber: dto.phoneNumber });
    
    if (!worker) {
      throw new BadRequestException('Worker not found');
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    worker.forceLogoutOtp = await bcrypt.hash(otp, 10);
    worker.forceLogoutOtpExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    await worker.save();

    await this.notificationsService.sendSmsOtp(dto.phoneNumber, otp);
    return { message: 'OTP sent successfully' };
  }

  async verifyForceLogout(dto: VerifyForceLogoutDto) {
    const worker = await this.workerModel.findOne({ phoneNumber: dto.phoneNumber });
    
    if (!worker?.forceLogoutOtp || !worker?.forceLogoutOtpExpiry) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    if (worker.forceLogoutOtpExpiry < new Date()) {
      throw new BadRequestException('OTP has expired');
    }

    if (!(await bcrypt.compare(dto.otp, worker.forceLogoutOtp))) {
      throw new UnauthorizedException('Invalid OTP');
    }

    worker.forceLogoutOtp = undefined;
    worker.forceLogoutOtpExpiry = undefined;
    worker.activeSessions = [];
    await worker.save();

    return { message: 'Force logout successful' };
  }
} 