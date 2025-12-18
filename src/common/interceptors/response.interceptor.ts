import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map, tap } from 'rxjs/operators';
import { Request } from 'express';

interface ApiResponse<T> {
  success: boolean;
  timestamp: string;
  path: string;
  data: T;
}

@Injectable()
export class ResponseInterceptor<T> implements NestInterceptor<
  T,
  ApiResponse<T>
> {
  intercept(
    context: ExecutionContext,
    next: CallHandler<T>,
  ): Observable<ApiResponse<T>> {
    const req = context.switchToHttp().getRequest<Request>();
    const start = Date.now();

    return next.handle().pipe(
      tap(() => {
        const duration = Date.now() - start;
        console.log(`[${req.method}] ${req.url} - ${duration}ms`);
      }),
      map((data) => ({
        success: true,
        timestamp: new Date().toISOString(),
        path: req.url,
        data,
      })),
    );
  }
}
