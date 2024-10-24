import { Controller, Get, Post, Body, Patch, Param, Delete, Res, Req, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { Request, Response } from 'express';
import { SignInAuthDto } from './dto/signInAuthDto';
import { log } from 'console';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('signup')
  async signup(@Body() createAuthDto: CreateAuthDto, @Res({ passthrough: true }) res: Response) {
    return this.authService.signup(createAuthDto, res);
  }

  @Post('signin')
  async signin(@Body() signInAuthDto: SignInAuthDto, @Res({ passthrough: true }) res: Response) {
    const tokens = await this.authService.signin(signInAuthDto, res);
    return tokens;
  }

  @Post('signout')
  async signout(@Body('userId') userId: number, @Res({ passthrough: true }) res: Response) {
    return this.authService.signout(userId, res);
  }

  @Post('refresh/:userId')
  async refreshTokens(@Param('userId') userId: number, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies['refresh_token'];  // Extract refresh token from the cookie
    console.log('Refresh token from cookie:', refreshToken);

    // Ensure userId is provided from the params
    if (!userId) {
      throw new UnauthorizedException('User ID is required');
    }

    return this.authService.refreshTokens(+userId, refreshToken, res);
  }

  @Post()
  create(@Body() createAuthDto: CreateAuthDto) {
    return this.authService.create(createAuthDto);
  }

  @Get()
  findAll() {
    return this.authService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.authService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
    return this.authService.update(+id, updateAuthDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.authService.remove(+id);
  }
}
