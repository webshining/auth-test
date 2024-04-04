import { RedisModule } from '@nestjs-modules/ioredis';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';

@Module({
    imports: [
        ConfigModule.forRoot({
            envFilePath: `.${process.env.NODE_ENV}.env`,
        }),
        RedisModule.forRootAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (configService: ConfigService) => {
                const RD_HOST = configService.get('RD_HOST');
                const RD_PORT: number = Number(configService.get('RD_PORT')) || 6379;
                const RD_DB: number = Number(configService.get('RD_DB')) || 5;
                const RD_PASS: string | undefined = configService.get('RD_PASS');
                let url: string = `redis://${RD_HOST}:${RD_PORT}/${RD_DB}`;
                if (RD_PASS) url = `redis://${RD_PASS}@${RD_HOST}:${RD_PORT}/${RD_DB}`;
                return {
                    type: 'single',
                    url: url,
                };
            },
        }),
        TypeOrmModule.forRootAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (configService: ConfigService) =>
                configService.get('NODE_ENV') == 'prod'
                    ? {
                          type: 'postgres',
                          database: configService.get('DB_NAME'),
                          username: configService.get('DB_USER'),
                          password: configService.get('DB_PASS'),
                          host: configService.get('DB_HOST'),
                          port: configService.get('DB_PORT'),
                          entities: [],
                          synchronize: true,
                          autoLoadEntities: true,
                      }
                    : {
                          type: 'sqlite',
                          database: 'database.sqlite3',
                          entities: [],
                          synchronize: true,
                          autoLoadEntities: true,
                      },
        }),
        UsersModule,
        AuthModule,
    ],
    providers: [],
})
export class AppModule {}
