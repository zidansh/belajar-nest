import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient {
  constructor() {
    super({
      datasources: {
        db: {
          url: 'postgresql://zidan:Xymwq12KK@localhost:5434/mydb?schema=public',
        },
      },
    });
  }
}
