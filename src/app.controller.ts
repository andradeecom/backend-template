import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('Health Check')
@Controller('healthcheck')
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @ApiOperation({ summary: 'Check if the application is running' })
  @ApiResponse({
    status: 200,
    description: 'Application is running successfully',
  })
  healthCheck(): object {
    return this.appService.healthCheck();
  }
}
