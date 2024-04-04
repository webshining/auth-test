import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthService } from 'src/auth/auth.service';
import { UsersController } from './users.controller';
import { User } from './users.entity';
import { UsersService } from './users.service';

@Module({
    imports: [TypeOrmModule.forFeature([User]), JwtModule, ConfigModule],
    providers: [UsersService, AuthService],
    controllers: [UsersController],
    exports: [UsersService],
})
export class UsersModule {}
