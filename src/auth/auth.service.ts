import { InjectRedis } from '@nestjs-modules/ioredis';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { CookieOptions, Response } from 'express';
import { Redis } from 'ioredis';
import { User } from 'src/users/users.entity';
import { UserLoginDto, UserRegisterDto } from 'src/users/users.types';
import { Repository } from 'typeorm';

@Injectable()
export class AuthService {
    constructor(
        private configService: ConfigService,
        private readonly jwtService: JwtService,
        @InjectRepository(User) private usersRepository: Repository<User>,
        @InjectRedis() private readonly redis: Redis,
    ) {}

    private readonly tokenCookieOptions: CookieOptions = {
        maxAge: this.configService.get('JWT_REFRESH_MINUTES') * 60 * 1000,
        httpOnly: true,
        sameSite: 'none',
        secure: true,
    };

    async login(res: Response, loginDto: UserLoginDto): Promise<{ accessToken: string; user: User }> {
        const { username, password } = loginDto;

        const user = await this.usersRepository.findOneBy({ username });
        if (!user) throw new UnauthorizedException(null, 'User not found');
        if (!(await this.comparePass(password, user.password))) throw new UnauthorizedException(null, 'Incorrect prev_password');

        const { accessToken, refreshToken } = await this.generateTokens({ sub: user.id });
        res.cookie('refreshToken', refreshToken, this.tokenCookieOptions);
        return { accessToken, user };
    }

    async register(res: Response, registerDto: UserRegisterDto): Promise<{ accessToken: string; user: User }> {
        const { email, username, password } = registerDto;

        let candidate = await this.usersRepository.findOneBy({ email });
        if (candidate) throw new UnauthorizedException(null, 'User with this email already exists');
        candidate = await this.usersRepository.findOneBy({ username });
        if (candidate) throw new UnauthorizedException(null, 'User with this username already exists');

        const hashPass = await this.hashPass(password);
        let user = await this.usersRepository.create({ username, email, password: hashPass });
        user = await this.usersRepository.save(user);

        const { accessToken, refreshToken } = await this.generateTokens({ sub: user.id });
        res.cookie('refreshToken', refreshToken, this.tokenCookieOptions);
        return { accessToken, user };
    }

    async refresh(res: Response, token: any): Promise<{ accessToken: string; user: User }> {
        if (!token) throw new UnauthorizedException();
        if (!(await this.isTokenExists(token))) throw new UnauthorizedException();
        await this.removeToken(token);

        try {
            const payload = this.jwtService.verify(token, { secret: this.configService.get('JWT_REFRESH_SECRET') || 'secret_refresh_key' });
            const { sub } = payload;

            const user = await this.usersRepository.findOneBy({ id: sub });
            if (!user) throw new UnauthorizedException();

            const { accessToken, refreshToken } = await this.generateTokens(this.configService, { sub: user.id });
            res.cookie('refreshToken', refreshToken, this.tokenCookieOptions);
            return { accessToken, user };
        } catch {
            res.clearCookie('refreshToken', { ...this.tokenCookieOptions, maxAge: 0 });
            throw new UnauthorizedException();
        }
    }

    async logout(res: Response, token: any) {
        await this.removeToken(token);
        res.clearCookie('refreshToken', { ...this.tokenCookieOptions, maxAge: 0 });
    }
    private async isTokenExists(token: string): Promise<boolean> {
        return (await this.redis.get(token)) ? true : false;
    }

    async hashPass(password: string): Promise<string> {
        return await bcrypt.hash(password, 7);
    }

    async comparePass(password: string, encrypted): Promise<boolean> {
        return await bcrypt.compare(password, encrypted);
    }

    private async generateTokens(accessPayload: object, refreshPayload?: object): Promise<{ accessToken: string; refreshToken: string }> {
        refreshPayload = refreshPayload ? refreshPayload : accessPayload;
        const accessToken = this.jwtService.sign(accessPayload, {
            secret: this.configService.get('JWT_ACCESS_SECRET') || 'secret_access_key',
            expiresIn: (this.configService.get('JWT_ACCESS_MINUTES') || 5) * 60,
        });
        const refreshToken = this.jwtService.sign(refreshPayload, {
            secret: this.configService.get('JWT_REFRESH_SECRET') || 'secret_refresh_key',
            expiresIn: (this.configService.get('JWT_REFRESH_MINUTES') || 60 * 24 * 30) * 60,
        });
        await this.saveToken(refreshToken);
        return { accessToken, refreshToken };
    }

    private async saveToken(token: string) {
        await this.redis.setex(token, (this.configService.get('JWT_REFRESH_MINUTES') || 60 * 24 * 30) * 60, 'refresh_token');
    }

    private async removeToken(token: string) {
        await this.redis.del(token);
    }
}
