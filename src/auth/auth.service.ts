import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from 'src/utils/dto';
import * as argon from 'argon2';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signIn(dto: AuthDto) {
    // find user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Credentials Incorrect');
    }

    // compare password
    const passwordMathes = await argon.verify(user.hash, dto.password);

    if (!passwordMathes) {
      throw new ForbiddenException('Credentials Incorrect');
    }

    delete user.hash;
    return user;
  }

  async signUp(dto: AuthDto) {
    // generate hash
    const hash = await argon.hash(dto.password);

    // save user
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;

      return user;
    } catch (err) {
      if (err.code === 'P2002') {
        throw new ForbiddenException('Credentials Taken');
      }
      throw err;
    }
  }
}
