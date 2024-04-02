import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import User from 'src/user/entities/user.entity';
import { UserModule } from 'src/user/user.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { EmailConfirmationModule } from 'src/email-confirmation/email-confirmation.module';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './strategy/local.strategy';
import { JwtStrategy } from './strategy/jwt.strategy';
import { JwtRefreshTokenStrategy } from './strategy/jwt-refresh-token.strategy';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
      UserModule,
      PassportModule,
      EmailConfirmationModule,
      // OtpModule,
      ConfigModule,
      JwtModule.registerAsync({
       imports: [ConfigModule],
       inject: [ConfigService],
       useFactory: async (configService: ConfigService) => ({
         secret: configService.get('JWT_SECRET'),
         signOptions: {
           expiresIn: `${configService.get('JWT_EXPIRATION_TIME')}s`,
         },
       }),
     }),
   ],
  controllers: [AuthController],
  providers: [AuthService,
    LocalStrategy, JwtStrategy, JwtRefreshTokenStrategy,
  ],
  exports:[AuthService]
})
export class AuthModule {}
