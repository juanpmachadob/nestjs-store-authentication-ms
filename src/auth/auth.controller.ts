import { Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  registerUser() {
    return { msg: 'register' };
  }

  @MessagePattern('auth.login.user')
  loginUser() {
    return { msg: 'login' };
  }

  @MessagePattern('auth.verify.user')
  verifyToken() {
    return { msg: 'verify' };
  }
}
