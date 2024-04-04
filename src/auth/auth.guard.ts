import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Request } from 'express';
import { User } from 'src/users/users.entity';
import { Repository } from 'typeorm';

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        @InjectRepository(User) private usersRepository: Repository<User>,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const req = context.switchToHttp().getRequest();
        const token = this.getBearerToken(req);
        if (!token) throw new UnauthorizedException();
        try {
            const { sub } = await this.jwtService.verifyAsync(token, { secret: this.configService.get('JWT_ACCESS_SECRET') || 'secret_access_key' });
            const user = await this.usersRepository.findOneBy({ id: sub });
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
