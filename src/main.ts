import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from "@nestjs/config";
import { ValidationPipe } from '@nestjs/common';
import *as cookieParser from 'cookie-parser';
import { LoggerFactory } from './common/LoggerFactory';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
//import cookieParser from 'cookie-parser';

async function bootstrap() {
 
 const app = await NestFactory.create<NestExpressApplication>(AppModule,{
  logger:LoggerFactory('PRODUCTMANAGEMENTAPI'),
 });
  app.useStaticAssets(join(__dirname, '..', 'uploads'), {
    index: false,
    prefix: 'uploads',
  });
  //const app = await NestFactory.create(AppModule);
  app.enableCors({
    origin:["http://localhost:3000"],
     //origin: '*',
     methods: ['GET', 'POST', 'PUT','DELETE'],
     allowedHeaders: ['Content-Type', 'Authorization']
   });
   app.use(cookieParser());
   app.useGlobalPipes(
     new ValidationPipe({
       whitelist:true,
       transform:true,
       forbidNonWhitelisted:true,
       transformOptions:{
       enableImplicitConversion:true,
       }
     })
   );
  const configService = app.get(ConfigService);
const PORT = +configService.get<number>("PORT")||7000;
await app.listen(PORT);

}
bootstrap();
