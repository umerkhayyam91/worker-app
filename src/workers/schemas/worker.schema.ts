import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type WorkerDocument = Worker & Document;

@Schema({ timestamps: true, collection: 'Users' })
export class Worker {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true, unique: true })
  phoneNumber: string;

  @Prop({ required: true })
  password: string;

  @Prop({ type: String, required: false })
  resetPasswordOtp?: string;

  @Prop({ type: Date, required: false })
  resetPasswordOtpExpiry?: Date;

  @Prop({ type: String, required: false })
  forceLogoutOtp?: string;

  @Prop({ type: Date, required: false })
  forceLogoutOtpExpiry?: Date;

  @Prop({ type: [String], default: [] })
  activeSessions: string[];
}

export const WorkerSchema = SchemaFactory.createForClass(Worker); 