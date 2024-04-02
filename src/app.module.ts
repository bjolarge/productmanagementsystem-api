import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import * as Joi from 'joi';
import { ConfigModule, ConfigService } from '@nestjs/config';
import {TypeOrmModule} from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { EmailConfirmationModule } from './email-confirmation/email-confirmation.module';
import { EmailModule } from './email/email.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
       //PORT
       PORT: Joi.number().required(),
       //...SECRETS
       JWT_SECRET: Joi.string().required(),
       JWT_EXPIRATION_TIME: Joi.string().required(),
       // Refresh token part
       JWT_ACCESS_TOKEN_SECRET: Joi.string().required(),
       JWT_ACCESS_TOKEN_EXPIRATION_TIME: Joi.string().required(),
       JWT_REFRESH_TOKEN_SECRET: Joi.string().required(),
       JWT_REFRESH_TOKEN_EXPIRATION_TIME: Joi.string().required(),
       //google Oauth
       GOOGLE_ID: Joi.string().required(),
       GOOGLE_SECRET: Joi.string().required(),
       //Email Service
       EMAIL_SERVICE: Joi.string().required(),
       EMAIL_USER: Joi.string().required(),
       EMAIL_PASSWORD: Joi.string().required(),
       EMAIL_CONFIRMATION_URL: Joi.string().required(),
       JWT_VERIFICATION_TOKEN_SECRET:Joi.string().required(),
       JWT_VERIFICATION_TOKEN_EXPIRATION_TIME:Joi.string().required(),
       
       
       // Environment options
       //NODE_ENV: Joi.string()
       // .required()
       // .valid(NODE_ENV.DEVELOPMENT, NODE_ENV.PRODUCTION),
     })
     }),
     
     // Typeorm model for mongodb
     TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
      type: 'mongodb',
      url: configService.get('MONGODB_CONNECTION_STRING'),
      //database: process.env.MONGODB_DATABASE,
      // entities: [
      //   __dirname + '/**/*.entity{.ts,.js}',
      // ],
      //ssl: true,
      autoLoadEntities:true,
      useUnifiedTopology: true,
      useNewUrlParser: true,
      synchronize:true,
    }),
    inject:[ConfigService],
  }),
     
     AuthModule,
     
     UserModule,
     
     EmailConfirmationModule,
     
     EmailModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
