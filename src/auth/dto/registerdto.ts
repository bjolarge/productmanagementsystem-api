import {IsEmail, IsNotEmpty, IsString, Matches, MinLength} from 'class-validator';
export class RegisterDto {
    @IsEmail()
    email: string;

    @IsString()
    @IsNotEmpty()
    name: string;

    @IsString()
    @IsNotEmpty()
    password: string;
    @IsString()
    @IsNotEmpty()
    address: string;
  
    // @ApiProperty({
    //   deprecated: true,
    //   description: 'Use the name property instead',
    // })
    // fullName: string;
  
    // @IsString()
    // @IsNotEmpty()
    // @MinLength(8)
    // password: string;
  
    // @ApiProperty({
    //   description: 'Has to match a regular expression: /^\\+[1-9]\\d{1,14}$/',
    //   example: '+123123123123',
    // })
    // @IsString()
    // @IsNotEmpty()
    // @Matches(/^\+[1-9]\d{1,14}$/)
    // phoneNumber: string;
}