import { Controller,  
  ClassSerializerInterceptor,
  UseInterceptors,
  Post,
  Body,
  UseGuards,
  Req, 
} from '@nestjs/common';
import { EmailConfirmationService } from './email-confirmation.service';
import ConfirmEmailDto from '../email-confirmation/dto/confirmEmail.dto';
import JwtAuthenticationGuard from '../auth/guard/jwt-authentication.guard';
import RequestWithUser from '../auth/requestWithUser.interface';
import { ObjectId } from 'typeorm';

@Controller('email-confirmation')
//@UseInterceptors(ClassSerializerInterceptor)
export class EmailConfirmationController {
  constructor(private readonly emailConfirmationService: EmailConfirmationService) {}
  @Post('confirm')
  async confirm(@Body() confirmationData: ConfirmEmailDto) {
    const email = await this.emailConfirmationService.decodeConfirmationToken(confirmationData.token);
    await this.emailConfirmationService.confirmEmail(email);
  }

  //resend confirmation Link
  // @Post('resend-confirmation-link')
  // @UseGuards(JwtAuthenticationGuard)
  // async resendConfirmationLink(@Req() request: RequestWithUser) {
  //   await this.emailConfirmationService.resendConfirmationLink(request.user.id);
  // }
}