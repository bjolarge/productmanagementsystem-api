import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import  UserService  from '../user/user.service';
//import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcryptjs';
import { RegisterDto } from './dto/registerdto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import TokenPayload  from './tokenPayload.interface';
import { InjectRepository } from '@nestjs/typeorm';
import User from '../user/entities/user.entity';
import { Repository } from 'typeorm';
// import { OtpService } from 'src/otp/otp.service';
// import { PasswordResetDto } from './dto/password-reset.dto';
// import { INormalResponse } from 'src/common/interface/index.interface';
// import { ResendCodeDto } from './dto/resend-code.dto';


@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private readonly usersService:UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    //private readonly otpService: OtpService,

  ) {}
 
  public async register(registrationData:RegisterDto) {
    const hashedPassword = await bcrypt.hash(registrationData.password, 10);
    try {
      const createdUser = await this.usersService.create({
        //refreshToken,
        ...registrationData,
        password: hashedPassword,
      });
     
      createdUser.password = undefined;
      return createdUser;
    } catch (error) {
      // if (error?.code === PostgresErrorCode.UniqueViolation) {
      //   throw new HttpException('User with that email already exists', HttpStatus.BAD_REQUEST);
      // }
      throw new HttpException('Something went wrong', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  //logging
  public async getAuthenticatedUser(email: string, plainTextPassword: string) {
    try {
      const user = await this.usersService.getByEmail(email);
      await this.verifyPassword(plainTextPassword, user.password);
      user.password = undefined;
      return user;
    } catch (error) {
      throw new HttpException('Wrong credentials provided', HttpStatus.BAD_REQUEST);
    }
  }
   
  private async verifyPassword(plainTextPassword: string, hashedPassword: string) {
    const isPasswordMatching = await bcrypt.compare(
      plainTextPassword,
      hashedPassword
    );
    if (!isPasswordMatching) {
      throw new HttpException('Wrong credentials provided', HttpStatus.BAD_REQUEST);
    }
  }

  public getCookieWithJwtToken(userId: number) {
    const payload: TokenPayload = { userId };
    const token = this.jwtService.sign(payload);
    return `Authentication=${token}; HttpOnly; Path=/; Max-Age=${this.configService.get('JWT_EXPIRATION_TIME')}`;
  }

  public getCookieForLogOut() {
   // return `Authentication=; HttpOnly; Path=/; Max-Age=0`;
   return [
    'Authentication=; HttpOnly; Path=/; Max-Age=0',
    'Refresh=; HttpOnly; Path=/; Max-Age=0'
  ];
  }
  //get cookies for logout
  public getCookiesForLogOut() {
    return [
      'Authentication=; HttpOnly; Path=/; Max-Age=0',
      'Refresh=; HttpOnly; Path=/; Max-Age=0',
    ];
  }

  public async removeRefreshToken(userId: number) {
    return this.usersRepository.update(userId, {
      currentHashedRefreshToken: null
    });
  }

  //get cookie with JWT TOKEN
  public getCookieWithJwtAccessToken(userId: number) {
    const payload: TokenPayload = { userId };
    const token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: `${this.configService.get('JWT_ACCESS_TOKEN_EXPIRATION_TIME')}`
    });
    return `Authentication=${token}; HttpOnly; Path=/; Max-Age=${this.configService.get('JWT_ACCESS_TOKEN_EXPIRATION_TIME')}`;
  }
 
  public getCookieWithJwtRefreshToken(userId: number) {
    const payload: TokenPayload = { userId };
    const token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: `${this.configService.get('JWT_REFRESH_TOKEN_EXPIRATION_TIME')}`
    });
    const cookie = `Refresh=${token}; HttpOnly; Path=/; Max-Age=${this.configService.get('JWT_REFRESH_TOKEN_EXPIRATION_TIME')}`;
    return {
      cookie,
      token,
    };
  }
  //getForgottenPasswordModel
  
  // async getForgottenPasswordModel(
  //   newPasswordToken:string
  // ):Promise<ForgottenPassword>{
  //   return await this.getForgottenPasswordModel.findOne({
  //     newPasswordToken:newPasswordToken
  //   });
  // }

  //logic to see if refresh token matches
  async getById(id) {
    const user = await this.usersRepository.findOneBy({ id });
    if (user) {
      return user;
    }
    throw new HttpException('User with this id does not exist', HttpStatus.NOT_FOUND);
  }
 
  async getUserIfRefreshTokenMatches(refreshToken: string, id: string) {
    const user = await this.getById(id);
 
    const isRefreshTokenMatching = await bcrypt.compare(
      refreshToken,
      user.currentHashedRefreshToken
    );
 
    if (isRefreshTokenMatching) {
      return user;
    }
  }

  // for chat service
  
  // public async getUserFromAuthenticationToken(token: string) {
  //   const payload: TokenPayload = this.jwtService.verify(token, {
  //     secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
  //   });
  //   if (payload.userId) {
  //     return this.usersService.getById(payload.userId);
  //   }
  // }

 
  //reset password
  // async passwordReset(
  //   //token: string,
  //   token:string,
  //   passwordResetDto: PasswordResetDto,
  // ): Promise<INormalResponse> {
  //   const { password } = passwordResetDto;
  //   const user = await this.verifyToken(token);

  //   if (!user || user === null) {
  //     return {
  //       message: 'user not found',
  //       status: HttpStatus.NOT_FOUND,
  //     };
  //   }
  //   if (token !== user.authToken) {
  //     return {
  //       message: 'invalid token',
  //       status: HttpStatus.BAD_REQUEST,
  //     };
  //   }

  //   if (!password) {
  //     return {
  //       message: 'please provide a reset password',
  //       status: HttpStatus.BAD_REQUEST,
  //     };
  //   }

  //   await this.usersService.update(user.id.toString(), { password });
  //   await this.usersService.updateUserSensitive(user.id.toString(), { authToken: null });

  //   return {
  //     message: 'password reset successfully',
  //     status: HttpStatus.CREATED,
  //   };
  // }

  //verify Token
  async verifyToken(token: string): Promise<User | null> {
    try {
      const decoded = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>('jWT_SECRET'),
      });

      const user = await this.usersService.findById(decoded.sub);
      if (!user || user === null) {
        throw new HttpException(
          'token could not be verified',
          HttpStatus.BAD_REQUEST,
        );
      }

      delete user.password;
      return user;
    } catch (err) {
      throw new HttpException('invalid token', HttpStatus.BAD_REQUEST);
    }
  }

  //forget password
  // async forgetPassword(resendCodeDto: ResendCodeDto): Promise<INormalResponse> {
  //   const { email } = resendCodeDto;
  //   const user = await this.usersService.findByEmail(email);
  //   if (!user || user === null) {
  //     return {
  //       message: 'user not found',
  //       status: HttpStatus.BAD_REQUEST,
  //     };
  //   }

  //   if (user.active === false) {
  //     await this.otpService.resendOtp(email, 'Account Activation');
  //     return {
  //       message:
  //         'Please check your email for OTP to activate your account before performing this action',
  //       status: HttpStatus.BAD_REQUEST,
  //     };
  //   }

  //   const payload = {
  //     email,
  //     sub: user.id,
  //   };

  //   const resetToken = await this.jwtService.signAsync(payload);

  //   await this.usersService.updateUserSensitive(user.id.toString(), {
  //     authToken: resetToken,
  //   });

  //   const resetLink = `Click the link to reset your password ${process.env.PASSWORD_RESET_URL_LINK}/auth/reset/password?token=${resetToken}`;

  //   await this.otpService.sendToken(email, 'Password Reset', resetLink);

  //   return {
  //     message: `please check your email for your password reset link or  click ${resetLink}`,
  //     status: HttpStatus.CREATED,
  //   };
  // }
}