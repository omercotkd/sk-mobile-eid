import { Module } from '@nestjs/common';
import { AuthController } from './auth/auth.controller';
import { AuthModule } from './auth';

@Module({
  imports: [AuthModule],
  controllers: [AuthController],
})
export class AppModule {}
