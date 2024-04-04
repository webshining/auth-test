import { Body, ClassSerializerInterceptor, Controller, Get, HttpCode, HttpStatus, Post, Req, Res, UseInterceptors } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Exclude } from 'class-transformer';
import { CookieOptions, Request, Response } from 'express';
import { UserLoginDto, UserRegisterDto } from 'src/users/users.types';
import { AuthService } from './auth.service';

export class UserEntity {
    id: number;
    firstName: string;
    lastName: string;

    @Exclude()
    password: string;

    constructor(partial: Partial<UserEntity>) {
        Object.assign(this, partial);
    }
}

@Controller('auth')
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly configService: ConfigService,
    ) {}
    private readonly tokenCookieOptions: CookieOptions = {
        maxAge: this.configService.get('JWT_REFRESH_MINUTES') * 60 * 1000,
        httpOnly: true,
        sameSite: 'none',
        secure: true,
    };

    @HttpCode(HttpStatus.OK)
    @Post('/login')
    async login(@Body() loginDto: UserLoginDto, @Res({ passthrough: true }) res: Response) {
        const { accessToken, refreshToken, user } = await this.authService.login(this.configService, loginDto);
        res.cookie('refreshToken', refreshToken, this.tokenCookieOptions);
        return { accessToken, user };
    }

    @HttpCode(HttpStatus.OK)
    @Post('/register')
    async register(@Body() registerDto: UserRegisterDto, @Res({ passthrough: true }) res: Response) {
        const { accessToken, refreshToken, user } = await this.authService.register(this.configService, registerDto);
        res.cookie('refreshToken', refreshToken, this.tokenCookieOptions);
        return { accessToken, user };
    }

    @Get('/refresh')
    async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const token = await req.cookies['refreshToken'];
        if (!token) res.clearCookie('refreshToken', { ...this.tokenCookieOptions, maxAge: 0 });
        const { accessToken, refreshToken, user } = await this.authService.refresh(this.configService, token);
        res.cookie('refreshToken', refreshToken, this.tokenCookieOptions);
        return { accessToken, user };
    }

    @Get('/logout')
    async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const token = await req.cookies['refreshToken'];
        await this.authService.logout(token);
        res.clearCookie('refreshToken', { ...this.tokenCookieOptions, maxAge: 0 });
        return 'Success!';
    }
}
