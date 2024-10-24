import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class SignInAuthDto {
  @IsEmail()
  readonly email: string;

  @IsNotEmpty()
  @IsString()
  readonly password: string;
}