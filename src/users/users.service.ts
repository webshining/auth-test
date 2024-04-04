import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { FindOptionsWhere, Repository } from 'typeorm';
import { User } from './users.entity';
import { UserCreateDto } from './users.types';

@Injectable()
export class UsersService {
    constructor(@InjectRepository(User) private usersRepository: Repository<User>) {}

    async findMany(options: FindOptionsWhere<User>): Promise<User[]> {
        return this.usersRepository.find({ where: options });
    }

    async findOne(options: FindOptionsWhere<User>): Promise<User | undefined> {
        return this.usersRepository.findOne({ where: options });
    }

    async create(userDto: UserCreateDto): Promise<User> {
        const user = this.usersRepository.create(userDto);
        return this.usersRepository.save(user);
    }

    async delete(options: FindOptionsWhere<User>): Promise<boolean> {
        this.usersRepository.delete(options);
        return true;
    }

    async update(options: FindOptionsWhere<User>, updatedUser: User): Promise<User | undefined> {
        const user = await this.findOne(options);
        if (!user) return undefined;
        return this.usersRepository.save(updatedUser);
    }
}
