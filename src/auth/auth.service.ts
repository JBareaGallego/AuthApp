import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';

import * as bcryptjs from "bcryptjs";

import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterUserDto } from './dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService : JwtService

  ) {}


  async create(createUserDto: CreateUserDto):Promise<User> {

    try{
      const {password, ...userData } = createUserDto;
    
      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData,
      });

      await newUser.save();
      const { password:_, ...user } = newUser.toJSON()
      return user

    }catch(error) {
      if(error.code === 11000){
        throw new BadRequestException (`${createUserDto.email } already exists`)}
      throw new InternalServerErrorException('somehting bad happened')
    }
    
  }

  async register(registerUserDto: RegisterUserDto):Promise<LoginResponse>{
    
    const user = await this.create(registerUserDto);

    return {
      user,
      token:this.getJwt({ id: user._id! })
    }
  }

  async login(loginDto : LoginDto):Promise<LoginResponse>{
    const {email, password} = loginDto;

    const user = await this.userModel.findOne({ email })
    if(!user){
      throw new UnauthorizedException('Not valid email');
    }
    if( !bcryptjs.compareSync(password, user.password!)){
      throw new UnauthorizedException('Password is not valid');
    }

    const { password:_, ...rest  } = user.toJSON()

    return {
      user: rest,
      token: this.getJwt({ id: user.id }),
    }

  }

  async findUserById( id: string){
    return this.userModel.findById(id).select('-password');
  }
  
  findAll():Promise<User[]> {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwt(payload : JwtPayload){
    const token = this.jwtService.sign(payload);
    return token;
  }

  checkToken(){
    
  }

}
