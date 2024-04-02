import { Module } from '@nestjs/common';
import { EmailConfirmationService } from './email-confirmation.service';
import { EmailConfirmationController } from './email-confirmation.controller';
import { EmailModule } from '../email/email.module';
// import { EmailModule } from 'src/email/email.module';
import { UserModule } from '../user/user.module';
// import { UserModule } from 'src/user/user.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import User from '../user/entities/user.entity';
// import User from 'src/user/entities/user.entity';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports:[
    TypeOrmModule.forFeature([User]),
    EmailModule, 
    UserModule,
    ConfigModule,
    JwtModule

  ],
  controllers: [EmailConfirmationController],
  providers: [EmailConfirmationService],
  exports:[EmailConfirmationService]
})
export class EmailConfirmationModule {}