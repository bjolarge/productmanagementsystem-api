import { 
  Controller, Get, Post, Body, Patch, Param, Delete, HttpCode, UseGuards, Req, 
  Res,ClassSerializerInterceptor, UseInterceptors, HttpStatus, Query,} from 
'@nestjs/common';
import { Request, Response} from 'express';
import { AuthService } from './auth.service';
import  UserService  from '../user/user.service';
import { RegisterDto } from './dto/registerdto';

import RequestWithUser from './requestWithUser.interface';
import JwtAuthenticationGuard from './guard/jwt-authentication.guard';
//import { LoginDto } from './dto/login.dto';
import JwtRefreshGuard from './guard/JwtRefreshGuard';
//import { EmailConfirmationService } from '../email-confirmation/email-confirmation.service';
import { INormalResponse } from 'src/common/interface/index.interface';
import { ConfigService } from '@nestjs/config';
import { EmailConfirmationService } from 'src/email-confirmation/email-confirmation.service';
import { LocalAuthenticationGuard } from './guard/localAuthentication.guard';
//import { Login } from './interfaces/Login.interface';
@Controller('auth')
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
  
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
   private readonly userService: UserService,
   private readonly emailConfirmationService: EmailConfirmationService
    ) {}

  @Post('register')
  async register(@Body() registrationData: RegisterDto) {  
    const user = await this.authService.register(registrationData);
    await this.emailConfirmationService.sendVerificationLink(registrationData.email);
    return user;
  }
 
  //real login with token feature
  @HttpCode(200)
  @UseGuards(LocalAuthenticationGuard)
  @Post('log-in')
  async logIn(@Req() request: RequestWithUser) {
    const { user } = request;
    const accessTokenCookie = this.authService.getCookieWithJwtAccessToken(
//user.id,
user.id,
    );
    const {
      cookie: refreshTokenCookie,
      token: refreshToken,
    } = this.authService.getCookieWithJwtRefreshToken(user.id);

    await this.userService.setCurrentRefreshToken(refreshToken, user.id);

    request.res.setHeader('Set-Cookie', [
      accessTokenCookie,
      refreshTokenCookie,
    ]);
    return user;

  }

  @UseGuards(LocalAuthenticationGuard)
  @Post('log-out')
  @HttpCode(200)
  async logOut(@Req() request: RequestWithUser) {
    await this.userService.removeRefreshToken(request.user.id);
    request.res.setHeader(
      'Set-Cookie',
      this.authService.getCookiesForLogOut(),
    );
  }


  //Login
  @UseGuards(JwtAuthenticationGuard)
  @Get()
  authenticate(@Req() request: RequestWithUser) {
    const user = request.user;
    user.password = undefined;
    console.log("Login")
    return user;
  }
  // handling the refresh token endpoint
  @UseGuards(JwtRefreshGuard)
  @Get('refresh')
  refresh(@Req() request: RequestWithUser) {
    const accessTokenCookie = this.authService.getCookieWithJwtAccessToken(request.user.id);
 
    request.res.setHeader('Set-Cookie', accessTokenCookie);
    return request.user;
  }

}