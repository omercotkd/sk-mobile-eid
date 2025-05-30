import { IsPhoneNumber, IsString, Length } from 'class-validator';

export class StartAuthDto {
  @IsString()
  @Length(11, 11)
  nationalIdentityNumber: string;

  @IsPhoneNumber()
  phoneNumber: string;
}
