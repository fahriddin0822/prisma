import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateAuthDto, UpdateAuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { Response } from 'express';
import { User } from '@prisma/client';
import Joi from 'joi';
import { SignInAuthDto } from './dto/signInAuthDto';
import { log } from 'console';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
  ) { }

  async generateTokens(user: User) {
    const payload = {
      id: user.id,
      name: user.name,
      email: user.email,
    };

    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(payload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);

    return { access_token, refresh_token };
  }


  async signup(createAuthDto: CreateAuthDto, res: Response) {
    const candidate = await this.prismaService.user.findUnique({
      where: { email: createAuthDto.email },
    });

    if (candidate) {
      throw new BadRequestException('This user already exists.');
    }

    if (createAuthDto.password !== createAuthDto.conformpassword) {
      throw new BadRequestException('Passwords do not match.');
    }

    const hashedPassword = await bcrypt.hash(createAuthDto.password, 7);

    const newUser = await this.prismaService.user.create({
      data: {
        email: createAuthDto.email,
        hashedpassword: hashedPassword,
      },
    });

    const tokens = await this.generateTokens(newUser);  // Awaiting token generation here

    await this.updateRefreshToken(newUser.id, tokens.refresh_token);

    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: +process.env.COOKIE_TIME,
      httpOnly: true,
    });

    return {
      newUser,
      tokens,  // Returning tokens here
    };
  }


  async signin(signInAuthDto: SignInAuthDto, res: Response) {
    const user = await this.prismaService.user.findUnique({
      where: { email: signInAuthDto.email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials.');
    }

    const passwordMatches = await bcrypt.compare(signInAuthDto.password, user.hashedpassword);
    if (!passwordMatches) {
      throw new UnauthorizedException('Invalid credentials.');
    }

    const tokens = this.generateTokens(user);
    await this.updateRefreshToken(user.id, (await tokens).refresh_token);

    res.cookie('refresh_token', (await tokens).refresh_token, {
      maxAge: +process.env.COOKIE_TIME,
      httpOnly: true,
    });

    return { access_token: (await tokens).access_token };
  }


  async signout(userId: number, res: Response) {
    await this.prismaService.user.updateMany({
      where: {
        id: userId,
        hashedRefreshToken: {
          not: null,
        },
      },
      data: {
        hashedRefreshToken: null,
      },
    });

    res.clearCookie('refresh_token');
    return { message: 'Signed out successfully' };
  }


  async refreshTokens(userId: number, refreshToken: string, res: Response) {
    try{
    // Ensure userId is being passed correctly
    if (!userId) {
      throw new UnauthorizedException('User ID is required for token refresh');
    }
  
    // Query user by ID (or use email if needed)
    const user = await this.prismaService.user.findUnique({
      where: { id: userId }, // Use userId to find the user
    });
  
    // If user or refresh token is missing in the database, throw an exception
    if (!user || !user.hashedRefreshToken) {
      throw new UnauthorizedException('Access Denied');
    }
  
    // Compare provided refresh token with stored hashed refresh token
    const refreshTokenMatches = await bcrypt.compare(refreshToken, user.hashedRefreshToken);
    if (!refreshTokenMatches) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  
    // Generate new access and refresh tokens
    const tokens = await this.generateTokens(user);
    await this.updateRefreshToken(user.id, tokens.refresh_token);
  
    // Set new refresh token in the cookie
    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: +process.env.COOKIE_TIME,
      httpOnly: true,
    });
  
    return { access_token: tokens.access_token };
    }catch(error){
      console.log(error);
    }
  }

  






  async updateRefreshToken(userId: number, refresh_token: string) {
    const hashedRefreshToken = await bcrypt.hash(refresh_token, 7);
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRefreshToken,
      },
    });
    return hashedRefreshToken;
  }


  create(createAuthDto: CreateAuthDto) {
    return 'This action adds a new auth';
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
