import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from 'src/utils/dto';
import * as argon from 'argon2';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}
  signIn() {}
  async signUp(dto: AuthDto) {
    // generate hash
    const hash = await argon.hash(dto.password);

    // save user
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
      },
    });

    return user;
  }
}
