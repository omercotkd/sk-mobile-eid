import { IsPhoneNumber, IsString, Length, IsUUID } from 'class-validator';

export class StartAuthDto {
  @IsString()
  @Length(11, 11)
  nationalIdentityNumber: string;
  // The testing phone numbers are not valid phone numbers,
  // so we use a string validator instead of IsPhoneNumber
  // @IsPhoneNumber()
  @IsString()
  @Length(9, 15)
  phoneNumber: string;
}


export class GetAuthStatusDto {
  @IsUUID()
  sessionId: string;
  @IsString()
  randomMessage: string;
}