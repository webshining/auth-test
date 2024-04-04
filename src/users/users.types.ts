import { IsEmail, IsNotEmpty } from 'class-validator';
export class UserRegisterDto {
    @IsEmail()
    @IsNotEmpty()
    email: string;
    @IsNotEmpty()
    username: string;
    @IsNotEmpty()
    password: string;
}
export class UserLoginDto {
    @IsNotEmpty()
    username: string;
    @IsNotEmpty()
    password: string;
}

export type UserCreateDto = UserRegisterDto;

export interface UserPatchDto {
    username?: string;
    email?: string;
    prev_password?: string;
    password?: string;
}
