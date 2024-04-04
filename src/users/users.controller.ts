import { Body, ClassSerializerInterceptor, Controller, Delete, Get, Patch, Req, Res, UseGuards, UseInterceptors } from '@nestjs/common';
import { Response } from 'express';
import { AuthGuard } from 'src/auth/auth.guard';
import { UsersService } from './users.service';
import { UserPatchDto } from './users.types';

@Controller('users')
@UseGuards(AuthGuard)
@UseInterceptors(ClassSerializerInterceptor)
export class UsersController {
    constructor(private readonly usersService: UsersService) {}

    @Get('/me')
    async me(@Req() req: any) {
        return req.user;
    }

    @Patch('/me')
    async me_patch(@Req() req: any, @Body() userPatchDto: UserPatchDto) {
        return await this.usersService.patch(req.user, userPatchDto);
    }

    @Delete('/me')
    async me_delete(@Req() req: any, @Res({ passthrough: true }) res: Response) {
        await this.usersService.delete(res, req.user, req.cookies['refreshToken']);
        return 'Success!';
    }
}
