import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import path from 'path';

import { DatabaseService } from './services/DatabaseService';
import { RedisService } from './services/RedisService';
import { Logger } from './utils/Logger';
import { ErrorHandler } from './middleware/ErrorHandler';
import { authMiddleware } from './middleware/AuthMiddleware';

// Route imports
import authRoutes from './routes/auth';
import userRoutes from './routes/users';
import applicationRoutes from './routes/applications';
import reviewRoutes from './routes/reviews';
import owaspRoutes from './routes/owasp';
import dashboardRoutes from './routes/dashboard';

// Load environment variables
dotenv.config();

class SecureArchServer {
  public app: express.Application;
  private port: number;
  private logger: Logger;

  constructor() {
    this.app = express();
    this.port = parseInt(process.env.PORT || '3001', 10);
    this.logger = new Logger('SecureArchServer');
    
    this.initializeMiddleware();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }

  private initializeMiddleware(): void {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          imgSrc: ["'self'", "data:", "https:"],
          scriptSrc: ["'self'", "'unsafe-eval'"], // For development
          connectSrc: ["'self'", "ws:", "wss:"], // For WebSocket connections
        },
      },
    }));

    // CORS configuration
    this.app.use(cors({
      origin: process.env.NODE_ENV === 'production' 
        ? ['https://securearch.com', 'https://app.securearch.com']
        : ['http://localhost:3000', 'http://localhost:3001'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
      message: {
        error: 'Too many requests from this IP, please try again later.',
        code: 'RATE_LIMIT_EXCEEDED',
      },
      standardHeaders: true,
      legacyHeaders: false,
    });
    this.app.use('/api/', limiter);

    // General middleware
    this.app.use(compression());
    this.app.use(morgan('combined', { 
      stream: { write: (message) => this.logger.info(message.trim()) } 
    }));
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Static files
    this.app.use('/uploads', express.static(path.join(__dirname, '../../uploads')));
    
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV || 'development',
      });
    });
  }

  private initializeRoutes(): void {
    const apiRouter = express.Router();

    // Public routes (no authentication required)
    apiRouter.use('/auth', authRoutes);
    
    // Protected routes (authentication required)
    apiRouter.use('/users', authMiddleware, userRoutes);
    apiRouter.use('/applications', authMiddleware, applicationRoutes);
    apiRouter.use('/reviews', authMiddleware, reviewRoutes);
    apiRouter.use('/owasp', authMiddleware, owaspRoutes);
    apiRouter.use('/dashboard', authMiddleware, dashboardRoutes);

    // Mount API routes
    this.app.use(`/api/${process.env.API_VERSION || 'v1'}`, apiRouter);

    // Serve frontend in production
    if (process.env.NODE_ENV === 'production') {
      this.app.use(express.static(path.join(__dirname, '../../client/build')));
      this.app.get('*', (req, res) => {
        res.sendFile(path.join(__dirname, '../../client/build/index.html'));
      });
    }

    // API documentation route
    if (process.env.SWAGGER_ENABLED === 'true') {
      this.app.get('/api/docs', (req, res) => {
        res.json({
          message: 'SecureArch Portal API Documentation',
          version: process.env.API_VERSION || 'v1',
          endpoints: {
            auth: '/api/v1/auth',
            users: '/api/v1/users',
            applications: '/api/v1/applications',
            reviews: '/api/v1/reviews',
            owasp: '/api/v1/owasp',
            dashboard: '/api/v1/dashboard',
          },
        });
      });
    }
  }

  private initializeErrorHandling(): void {
    // 404 handler
    this.app.use((req, res) => {
      res.status(404).json({
        error: 'Endpoint not found',
        code: 'ENDPOINT_NOT_FOUND',
        path: req.path,
        method: req.method,
      });
    });

    // Global error handler
    this.app.use(ErrorHandler.handle);
  }

  public async start(): Promise<void> {
    try {
      // Initialize database connection
      await DatabaseService.initialize();
      this.logger.info('Database connection established');

      // Initialize Redis connection
      await RedisService.initialize();
      this.logger.info('Redis connection established');

      // Start server
      this.app.listen(this.port, () => {
        this.logger.info(`🚀 SecureArch Portal server running on port ${this.port}`);
        this.logger.info(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
        this.logger.info(`🔗 API Base URL: http://localhost:${this.port}/api/${process.env.API_VERSION || 'v1'}`);
        
        if (process.env.SWAGGER_ENABLED === 'true') {
          this.logger.info(`📖 API Documentation: http://localhost:${this.port}/api/docs`);
        }
      });

    } catch (error) {
      this.logger.error('Failed to start server:', error);
      process.exit(1);
    }
  }

  public async stop(): Promise<void> {
    try {
      await DatabaseService.close();
      await RedisService.close();
      this.logger.info('Server stopped gracefully');
    } catch (error) {
      this.logger.error('Error stopping server:', error);
    }
  }
}

// Create and start server
const server = new SecureArchServer();

// Graceful shutdown handling
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await server.stop();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  await server.stop();
  process.exit(0);
});

// Start the server
if (require.main === module) {
  server.start().catch((error) => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });
}

export default server; 