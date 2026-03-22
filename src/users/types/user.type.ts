import type { User } from 'src/generated/prisma/client';

export type UserType = User;
export type UserResponse = Omit<User, 'password'>;
