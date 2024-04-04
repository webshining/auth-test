import { BadRequestException, ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { isEmail } from 'class-validator';
import { Response } from 'express';
import { AuthService } from 'src/auth/auth.service';
import { Repository } from 'typeorm';
import { User } from './users.entity';
import { UserPatchDto } from './users.types';

@Injectable()
export class UsersService {
    constructor(
        private readonly authService: AuthService,
        @InjectRepository(User) private usersRepository: Repository<User>,
    ) {}

    async patch(user: User, userPatchDto: UserPatchDto) {
        const { username, email, prev_password, password } = userPatchDto;

        if (username) {
            if (username !== user.username && (await this.usersRepository.findOneBy({ username }))) throw new ConflictException(null, 'User with this username already exists');
            user.username = username;
        }
        if (email) {
            if (!isEmail(email)) throw new BadRequestException(null, 'Invalid email format');
            if (email !== user.email && (await this.usersRepository.findOneBy({ email }))) throw new ConflictException(null, 'User with this email already exists');
            user.email = email;
        }
        if (prev_password || password) {
            if (!prev_password || !password) throw new BadRequestException(null, "Missing 'password' or 'prev_password'");
            if (!(await this.authService.comparePass(prev_password, user.password))) throw new UnauthorizedException(null, 'Incorrect prev_password');
            user.password = await this.authService.hashPass(password);
        }

        return await this.usersRepository.save(user);
    }

    async delete(res: Response, user: User, token: string | undefined) {
        await this.usersRepository.delete({ id: user.id });
        await this.authService.logout(res, token);
    }
}
