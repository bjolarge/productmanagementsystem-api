import { PartialType } from '@nestjs/mapped-types';
import { CreateEmailConfirmationDto } from './create-email-confirmation.dto';

export class UpdateEmailConfirmationDto extends PartialType(CreateEmailConfirmationDto) {}
