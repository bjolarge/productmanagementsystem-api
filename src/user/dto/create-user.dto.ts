import {IsEmail, IsString, IsStrongPassword} from 'class-validator';

export class CreateUserDto {
    @IsString()
    @IsEmail()
    email: string;
    @IsString()
    name: string;
    @IsString()
    @IsStrongPassword()
    password: string;
    // @IsString()
    // refreshToken: string;
}

function UniqueOnDatabase(Customer: any): (target: CreateUserDto, propertyKey: "email") => void {
    throw new Error('Function not implemented.');
}
