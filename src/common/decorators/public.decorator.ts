import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';

/** Opts a route out of the session guard (login, register, password reset...). */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
