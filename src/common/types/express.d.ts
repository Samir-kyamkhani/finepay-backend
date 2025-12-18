import 'express-serve-static-core';
import { SessionUser } from './auth.type';

declare module 'express-serve-static-core' {
  interface Request {
    user?: SessionUser;
    cookies: {
      access_token?: string;
    };
  }
}
