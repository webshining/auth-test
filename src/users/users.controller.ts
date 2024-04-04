import { InjectRedis } from '@nestjs-modules/ioredis';
import { Body, ClassSerializerInterceptor, Controller, Delete, Get, Patch, Req, Res, UnauthorizedException, UseGuards, UseInterceptors } from '@nestjs/common';
import { isEmail } from 'class-validator';
import { Response } from 'express';
import { Redis } from 'ioredis';
import { AuthGuard } from 'src/auth/auth.guard';
import { AuthService } from './../auth/auth.service';
import { User } from './users.entity';
import { UsersService } from './users.service';
import { UserPatchDto } from './users.types';

@Controller('users')
@UseInterceptors(ClassSerializerInterceptor)
export class UsersController {
    constructor(
        private readonly usersService: UsersService,
        private readonly authService: AuthService,
        @InjectRedis() private readonly redis: Redis,
    ) {}

    @UseGuards(AuthGuard)
    @Get('/me')
    async me(@Req() req: any) {
        return req.user;
    }

    @UseGuards(AuthGuard)
    @Patch('/me')
    async me_patch(@Req() req: any, @Body() userDto: UserPatchDto) {
        const { username, email, prev_password, password } = userDto;
        if (username && (await this.usersService.findOne({ username }))) throw new UnauthorizedException(null, 'User with this username already exists');
        if (email && (await this.usersService.findOne({ email }))) throw new UnauthorizedException(null, 'User with this email already exists');
        const user: User = req.user;
        if (email && isEmail(email)) user.email = email;
        if (username) user.username = username;
        if (password && prev_password && (await this.authService.comparePass(prev_password, user.password))) user.password = await this.authService.hashPass(password);
        return await this.usersService.update({ id: user.id }, user);
    }

    @UseGuards(AuthGuard)
    @Delete('/me')
    async me_delete(@Req() req: any, @Res() res: Response) {
        const token = await req.cookies['refreshToken'];
        const user: User = req.user;
        await this.usersService.delete({ id: user.id });
        await this.redis.del(token);
        res.clearCookie('refreshToken', { ...this, maxAge: 0 });
        return 'Success!';
    }
}
