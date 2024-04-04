import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(
        private readonly jwtService: JwtService,
        private readonly usersService: UsersService,
        private readonly configService: ConfigService,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const req = context.switchToHttp().getRequest();
        const token = this.getBearerToken(req);
        if (!token) throw new UnauthorizedException();
        try {
            const { sub } = await this.jwtService.verifyAsync(token, { secret: this.configService.get('JWT_ACCESS_SECRET') || 'secret_access_key' });
            const user = await this.usersService.findOne({ id: sub });
            if (!user) throw new UnauthorizedException();
            req.user = user;
        } catch {
            throw new UnauthorizedException();
        }
        return true;
    }

    private getBearerToken(request: Request): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }
}
