import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import * as cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

const PORT = process.env.PORT || 4000;

const bootstrap = async () => {
    const app = await NestFactory.create(AppModule);
    app.setGlobalPrefix('api');

    app.useGlobalPipes(new ValidationPipe());
    app.use(cookieParser());
    await app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
};

bootstrap();
