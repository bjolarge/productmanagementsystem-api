import { Controller, Get, Post, Body, Patch, Param, Delete, Query, Put } from '@nestjs/common';
import UserService  from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PaginationQueryDto } from '../common/dto/pagination-query.dto/pagination-query.dto';
import { UpdateUserSensitive } from './dto/update-user-sensitive.dto';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

 

  // @Post('/googleuser')
  // createUserWithGoogle(@Body()email:string,name:string) {
  //   console.error('Whatsup');
  //   return this.userService.createWithGoogle(email,name);
  // }

  @Get()
  findAll(@Query()paginationQuery:PaginationQueryDto) {
    return this.userService.findAll(paginationQuery);
  }

  @Get('email')
  findOne(@Param('id') email: string) {
    return this.userService.getByEmail(email);
  }

  @Get('/count')
  findAllUser() {
    return this.userService.findusercount();
  }

  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
  //   return this.userService.update(+id, updateUserDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.userService.remove(+id);
  // }
}