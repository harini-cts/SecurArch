import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { Logger } from '../utils/Logger';

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: string;
  organizationId: string;
  permissions: string[];
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
}

class AuthMiddleware {
  private logger: Logger;

  constructor() {
    this.logger = new Logger('AuthMiddleware');
  }

  public authenticate = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const token = this.extractToken(req);
      
      if (!token) {
        this.logger.security('Authentication failed: No token provided', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          path: req.path,
        });
        
        res.status(401).json({
          error: 'Authentication required',
          code: 'AUTH_TOKEN_MISSING',
        });
        return;
      }

      const decoded = this.verifyToken(token);
      req.user = decoded;

      this.logger.audit('User authenticated', decoded.id, req.path, {
        method: req.method,
        ip: req.ip,
      });

      next();
    } catch (error) {
      this.logger.security('Authentication failed: Invalid token', {
        error: error instanceof Error ? error.message : 'Unknown error',
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
      });

      res.status(401).json({
        error: 'Invalid or expired token',
        code: 'AUTH_TOKEN_INVALID',
      });
    }
  };

  public authorize = (requiredPermissions: string | string[]) => {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
      if (!req.user) {
        res.status(401).json({
          error: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      const permissions = Array.isArray(requiredPermissions) 
        ? requiredPermissions 
        : [requiredPermissions];

      const hasPermission = permissions.some(permission => 
        req.user!.permissions.includes(permission) || 
        req.user!.role === 'admin'
      );

      if (!hasPermission) {
        this.logger.security('Authorization failed: Insufficient permissions', {
          userId: req.user.id,
          role: req.user.role,
          requiredPermissions: permissions,
          userPermissions: req.user.permissions,
          path: req.path,
          method: req.method,
        });

        res.status(403).json({
          error: 'Insufficient permissions',
          code: 'AUTH_INSUFFICIENT_PERMISSIONS',
          required: permissions,
        });
        return;
      }

      this.logger.audit('User authorized', req.user.id, req.path, {
        permissions,
        method: req.method,
      });

      next();
    };
  };

  public requireRole = (requiredRoles: string | string[]) => {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
      if (!req.user) {
        res.status(401).json({
          error: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
        return;
      }

      const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
      
      if (!roles.includes(req.user.role)) {
        this.logger.security('Authorization failed: Insufficient role', {
          userId: req.user.id,
          userRole: req.user.role,
          requiredRoles: roles,
          path: req.path,
          method: req.method,
        });

        res.status(403).json({
          error: 'Insufficient role',
          code: 'AUTH_INSUFFICIENT_ROLE',
          required: roles,
          current: req.user.role,
        });
        return;
      }

      next();
    };
  };

  private extractToken(req: Request): string | null {
    // Check Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    // Check query parameter (for file downloads, etc.)
    const queryToken = req.query.token as string;
    if (queryToken) {
      return queryToken;
    }

    return null;
  }

  private verifyToken(token: string): AuthenticatedUser {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error('JWT_SECRET not configured');
    }

    const decoded = jwt.verify(token, secret) as any;
    
    // Validate token structure
    if (!decoded.id || !decoded.email || !decoded.role) {
      throw new Error('Invalid token structure');
    }

    return {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
      organizationId: decoded.organizationId,
      permissions: decoded.permissions || [],
    };
  }

  public generateToken(user: {
    id: string;
    email: string;
    role: string;
    organizationId: string;
    permissions: string[];
  }): string {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error('JWT_SECRET not configured');
    }

    const payload = {
      id: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organizationId,
      permissions: user.permissions,
    };

    return jwt.sign(payload, secret, {
      expiresIn: process.env.JWT_EXPIRES_IN || '8h',
    });
  }

  public generateRefreshToken(userId: string): string {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error('JWT_SECRET not configured');
    }

    return jwt.sign(
      { userId, type: 'refresh' }, 
      secret, 
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );
  }

  public verifyRefreshToken(token: string): { userId: string } {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error('JWT_SECRET not configured');
    }

    const decoded = jwt.verify(token, secret) as any;
    
    if (decoded.type !== 'refresh' || !decoded.userId) {
      throw new Error('Invalid refresh token');
    }

    return { userId: decoded.userId };
  }
}

// Create singleton instance
const authMiddleware = new AuthMiddleware();

// Export middleware functions
export const authenticate = authMiddleware.authenticate;
export const authorize = authMiddleware.authorize;
export const requireRole = authMiddleware.requireRole;
export const generateToken = authMiddleware.generateToken.bind(authMiddleware);
export const generateRefreshToken = authMiddleware.generateRefreshToken.bind(authMiddleware);
export const verifyRefreshToken = authMiddleware.verifyRefreshToken.bind(authMiddleware);

// Export the middleware instance for direct use
export { authMiddleware }; 