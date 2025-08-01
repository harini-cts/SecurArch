import * as winston from 'winston';
import * as path from 'path';

export enum LogLevel {
  ERROR = 'error',
  WARN = 'warn',
  INFO = 'info',
  DEBUG = 'debug',
}

export class Logger {
  private logger: winston.Logger;
  private context: string;

  constructor(context: string = 'App') {
    this.context = context;
    this.logger = this.createLogger();
  }

  private createLogger(): winston.Logger {
    const logFormat = winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.errors({ stack: true }),
      winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
        const metaString = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
        const stackString = stack ? `\n${stack}` : '';
        return `${timestamp} [${level.toUpperCase()}] [${this.context}]: ${message}${metaString}${stackString}`;
      })
    );

    const transports: winston.transport[] = [
      new winston.transports.Console({
        level: process.env.LOG_LEVEL || 'info',
        format: winston.format.combine(
          winston.format.colorize(),
          logFormat
        ),
      }),
    ];

    // Add file transport in production
    if (process.env.NODE_ENV === 'production' || process.env.LOG_FILE) {
      const logDir = path.dirname(process.env.LOG_FILE || 'logs/app.log');
      
      transports.push(
        new winston.transports.File({
          filename: process.env.LOG_FILE || 'logs/app.log',
          level: 'info',
          format: logFormat,
          maxsize: this.parseSize(process.env.LOG_MAX_SIZE || '10m'),
          maxFiles: parseInt(process.env.LOG_MAX_FILES || '5', 10),
          tailable: true,
        })
      );

      // Separate error log file
      transports.push(
        new winston.transports.File({
          filename: path.join(logDir, 'error.log'),
          level: 'error',
          format: logFormat,
          maxsize: this.parseSize(process.env.LOG_MAX_SIZE || '10m'),
          maxFiles: parseInt(process.env.LOG_MAX_FILES || '5', 10),
          tailable: true,
        })
      );
    }

    return winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: logFormat,
      transports,
      exitOnError: false,
    });
  }

  private parseSize(size: string): number {
    const units: { [key: string]: number } = {
      b: 1,
      k: 1024,
      m: 1024 * 1024,
      g: 1024 * 1024 * 1024,
    };

    const match = size.toLowerCase().match(/^(\d+)([kmg]?)b?$/);
    if (!match) return 10 * 1024 * 1024; // Default 10MB

    const value = parseInt(match[1], 10);
    const unit = match[2] || 'b';
    return value * units[unit];
  }

  public error(message: string, error?: Error | any, meta?: any): void {
    this.logger.error(message, { 
      error: error instanceof Error ? error.message : error,
      stack: error instanceof Error ? error.stack : undefined,
      ...meta 
    });
  }

  public warn(message: string, meta?: any): void {
    this.logger.warn(message, meta);
  }

  public info(message: string, meta?: any): void {
    this.logger.info(message, meta);
  }

  public debug(message: string, meta?: any): void {
    this.logger.debug(message, meta);
  }

  public log(level: LogLevel, message: string, meta?: any): void {
    this.logger.log(level, message, meta);
  }

  // Security-specific logging methods
  public security(event: string, details: any): void {
    this.logger.warn(`SECURITY: ${event}`, {
      securityEvent: true,
      event,
      ...details,
    });
  }

  public audit(action: string, userId: string, resource: string, details?: any): void {
    this.logger.info(`AUDIT: ${action}`, {
      auditEvent: true,
      action,
      userId,
      resource,
      timestamp: new Date().toISOString(),
      ...details,
    });
  }

  public performance(operation: string, duration: number, meta?: any): void {
    this.logger.info(`PERF: ${operation}`, {
      performanceEvent: true,
      operation,
      duration,
      unit: 'ms',
      ...meta,
    });
  }

  // Static methods for global logging
  public static createLogger(context: string): Logger {
    return new Logger(context);
  }

  public static error(message: string, error?: Error | any, context: string = 'Global'): void {
    const logger = new Logger(context);
    logger.error(message, error);
  }

  public static warn(message: string, context: string = 'Global'): void {
    const logger = new Logger(context);
    logger.warn(message);
  }

  public static info(message: string, context: string = 'Global'): void {
    const logger = new Logger(context);
    logger.info(message);
  }

  public static debug(message: string, context: string = 'Global'): void {
    const logger = new Logger(context);
    logger.debug(message);
  }
} 