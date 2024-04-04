import { InjectRedis } from '@nestjs-modules/ioredis';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Redis } from 'ioredis';
import { User } from 'src/users/users.entity';
import { UsersService } from 'src/users/users.service';
import { UserLoginDto, UserRegisterDto } from 'src/users/users.types';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
        @InjectRedis() private readonly redis: Redis,
    ) {}

    async login(configService: ConfigService, loginDto: UserLoginDto): Promise<{ accessToken: string; refreshToken: string; user: User }> {
        const { username, password } = loginDto;
        const user = await this.usersService.findOne({ username });
        if (!user) throw new UnauthorizedException(null, 'User not found');
        if (!(await this.comparePass(password, user.password))) throw new UnauthorizedException(null, 'Wrong password');
        const { accessToken, refreshToken } = await this.generateTokens(configService, { sub: user.id });
        return { accessToken, refreshToken, user };
    }

    async register(configService: ConfigService, registerDto: UserRegisterDto): Promise<{ accessToken: string; refreshToken: string; user: User }> {
        const { email, username, password } = registerDto;
        let candidate = await this.usersService.findOne({ email });
        if (candidate) throw new UnauthorizedException(null, 'User with this email already exists');
        candidate = await this.usersService.findOne({ username });
        if (candidate) throw new UnauthorizedException(null, 'User with this username already exists');
        const hashPass = await this.hashPass(password);
        const user = await this.usersService.create({ username, email, password: hashPass });
        const { accessToken, refreshToken } = await this.generateTokens(configService, { sub: user.id });
        return { accessToken, refreshToken, user };
    }

    async refresh(configService: ConfigService, token: any): Promise<{ accessToken: string; refreshToken: string; user: User }> {
        if (!token) throw new UnauthorizedException();
        if (!(await this.isTokenExists(token))) throw new UnauthorizedException();
        await this.removeToken(token);
        try {
            const payload = this.jwtService.verify(token, { secret: configService.get('JWT_REFRESH_SECRET') || 'secret_refresh_key' });
            const { sub } = payload;
            const user = await this.usersService.findOne({ id: sub });
            if (!user) throw new UnauthorizedException();
            const { accessToken, refreshToken } = await this.generateTokens(configService, { sub: user.id });
            return { accessToken, refreshToken, user };
        } catch {
            throw new UnauthorizedException();
        }
    }

    async logout(token: any) {
        await this.removeToken(token);
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

    private async generateTokens(configService: ConfigService, accessPayload: object, refreshPayload?: object): Promise<{ accessToken: string; refreshToken: string }> {
        refreshPayload = refreshPayload ? refreshPayload : accessPayload;
        const accessToken = this.jwtService.sign(accessPayload, {
            secret: configService.get('JWT_ACCESS_SECRET') || 'secret_access_key',
            expiresIn: (configService.get('JWT_ACCESS_MINUTES') || 5) * 60,
        });
        const refreshToken = this.jwtService.sign(refreshPayload, {
            secret: configService.get('JWT_REFRESH_SECRET') || 'secret_refresh_key',
            expiresIn: (configService.get('JWT_REFRESH_MINUTES') || 60 * 24 * 30) * 60,
        });
        await this.saveToken(configService, refreshToken);
        return { accessToken, refreshToken };
    }

    private async saveToken(configService: ConfigService, token: string) {
        await this.redis.setex(token, (configService.get('JWT_REFRESH_MINUTES') || 60 * 24 * 30) * 60, 'refresh_token');
    }

    private async removeToken(token: string) {
        await this.redis.del(token);
    }
}
