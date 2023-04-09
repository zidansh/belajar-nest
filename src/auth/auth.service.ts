import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from 'src/auth/utils/dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { access } from 'fs';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signIn(dto: AuthDto): Promise<{ access_token: string }> {
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
    return this.signToken(user.id, user.email);
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

      return this.signToken(user.id, user.email);
    } catch (err) {
      if (err.code === 'P2002') {
        throw new ForbiddenException('Credentials Taken');
      }
      throw err;
    }
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: this.config.get('JWT_SECRET'),
    });

    return {
      access_token: token,
    };
  }
}
