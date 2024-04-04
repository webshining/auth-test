import { Body, ClassSerializerInterceptor, Controller, Get, HttpCode, HttpStatus, Post, Req, Res, UseInterceptors } from '@nestjs/common';
import { Request, Response } from 'express';
import { UserLoginDto, UserRegisterDto } from 'src/users/users.types';
import { AuthService } from './auth.service';

@Controller('auth')
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @HttpCode(HttpStatus.OK)
    @Post('/login')
    async login(@Body() loginDto: UserLoginDto, @Res({ passthrough: true }) res: Response) {
        const { accessToken, user } = await this.authService.login(res, loginDto);
        return { accessToken, user };
    }

    @HttpCode(HttpStatus.OK)
    @Post('/register')
    async register(@Body() registerDto: UserRegisterDto, @Res({ passthrough: true }) res: Response) {
        const { accessToken, user } = await this.authService.register(res, registerDto);
        return { accessToken, user };
    }

    @Get('/refresh')
    async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const { accessToken, user } = await this.authService.refresh(res, req.cookies['refreshToken']);
        return { accessToken, user };
    }

    @Get('/logout')
    async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        await this.authService.logout(res, req.cookies['refreshToken']);
        return 'Success!';
    }
}
