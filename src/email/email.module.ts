import { Module } from '@nestjs/common';
import { EmailService } from './email.service';
import { ConfigModule } from '@nestjs/config';
import { ConfigurableEmailModule } from './email.module-definition';
import { EmailController } from './email.controller';
//import { EmailController } from './email.controller';

@Module({
  imports: [ConfigModule],
  controllers: [EmailController],
  providers: [EmailService],
  exports: [EmailService]
})
export class EmailModule extends ConfigurableEmailModule {}