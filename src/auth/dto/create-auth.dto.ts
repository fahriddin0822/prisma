import { IsEmail, IsNotEmpty, IsOptional, IsString } from "class-validator";

export class CreateAuthDto {

    @IsOptional()
    @IsString()
    name?:string

    @IsEmail()
    readonly email?:string

    @IsNotEmpty()
    @IsString()
    readonly password: string

    @IsNotEmpty()
    @IsString()
    readonly conformpassword: string

}
