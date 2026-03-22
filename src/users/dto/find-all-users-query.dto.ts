import { IsEnum, IsNumberString, IsOptional, IsString } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { type UserRoleType, UserRoleValues } from '../types/user-roles.type';

export class FindAllUsersQueryDto {
  @ApiPropertyOptional({ example: '1' })
  @IsNumberString()
  @IsOptional()
  page?: string;

  @ApiPropertyOptional({ example: '10' })
  @IsNumberString()
  @IsOptional()
  limit?: string;

  @ApiPropertyOptional({
    enum: UserRoleValues,
    example: UserRoleValues.STUDENT,
  })
  @IsEnum(UserRoleValues)
  @IsOptional()
  role?: UserRoleType;

  @ApiPropertyOptional({ example: 'john' })
  @IsString()
  @IsOptional()
  search?: string;
}
