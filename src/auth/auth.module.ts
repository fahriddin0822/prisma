import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  imports: [
    JwtModule.register({
      secret: 'secret-key',
      signOptions: { expiresIn: '60m' },
    }),
    PrismaModule
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaService],
})
export class AuthModule { }
