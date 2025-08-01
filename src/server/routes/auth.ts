import { Router, Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { generateToken, generateRefreshToken, verifyRefreshToken } from '../middleware/AuthMiddleware';
import { db } from '../services/DatabaseService';
import { Logger } from '../utils/Logger';

const router = Router();
const logger = new Logger('AuthRoutes');

interface User {
  id: string;
  email: string;
  password_hash: string;
  first_name: string;
  last_name: string;
  role: string;
  organization_id: string;
  is_active: boolean;
}

// Validation rules
const registerValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('firstName').trim().isLength({ min: 1 }).withMessage('First name is required'),
  body('lastName').trim().isLength({ min: 1 }).withMessage('Last name is required'),
  body('organizationName').optional().trim(),
];

const loginValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 1 }).withMessage('Password is required'),
];

// Register new user
router.post('/register', registerValidation, async (req: Request, res: Response) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: errors.array(),
      });
    }

    const { email, password, firstName, lastName, organizationName } = req.body;

    // Check if user already exists
    const existingUser = await db.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        error: 'User already exists',
        code: 'USER_EXISTS',
      });
    }

    // Hash password
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create organization if provided
    let organizationId = null;
    if (organizationName) {
      const orgResult = await db.query(
        'INSERT INTO organizations (id, name) VALUES ($1, $2) RETURNING id',
        [uuidv4(), organizationName]
      );
      organizationId = orgResult.rows[0].id;
    }

    // Create user
    const userId = uuidv4();
    const userResult = await db.query(`
      INSERT INTO users (id, email, password_hash, first_name, last_name, organization_id, role)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, email, first_name, last_name, role, organization_id
    `, [userId, email, passwordHash, firstName, lastName, organizationId, 'user']);

    const user = userResult.rows[0];

    logger.audit('User registered', user.id, 'registration', {
      email: user.email,
      organizationId: user.organization_id,
    });

    // Generate tokens
    const accessToken = generateToken({
      id: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organization_id,
      permissions: ['review:read', 'review:create'], // Default permissions
    });

    const refreshToken = generateRefreshToken(user.id);

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        organizationId: user.organization_id,
      },
      tokens: {
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresIn: process.env.JWT_EXPIRES_IN || '8h',
      },
    });

  } catch (error) {
    logger.error('Registration failed', error);
    res.status(500).json({
      error: 'Registration failed',
      code: 'REGISTRATION_ERROR',
    });
  }
});

// Login user
router.post('/login', loginValidation, async (req: Request, res: Response) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: errors.array(),
      });
    }

    const { email, password } = req.body;

    // Get user with permissions
    const userResult = await db.query(`
      SELECT u.*, array_agg(DISTINCT ur.role_id) as role_ids
      FROM users u
      LEFT JOIN user_roles ur ON u.id = ur.user_id
      WHERE u.email = $1 AND u.is_active = true
      GROUP BY u.id
    `, [email]);

    if (userResult.rows.length === 0) {
      logger.security('Login failed: User not found', {
        email,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      return res.status(401).json({
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS',
      });
    }

    const user: User = userResult.rows[0];

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      logger.security('Login failed: Invalid password', {
        userId: user.id,
        email: user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      return res.status(401).json({
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS',
      });
    }

    // Get user permissions based on role
    const permissions = await getUserPermissions(user.role);

    logger.audit('User logged in', user.id, 'authentication', {
      email: user.email,
      ip: req.ip,
    });

    // Generate tokens
    const accessToken = generateToken({
      id: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organization_id,
      permissions,
    });

    const refreshToken = generateRefreshToken(user.id);

    // Update last login
    await db.query(
      'UPDATE users SET last_login_at = NOW(), login_count = login_count + 1 WHERE id = $1',
      [user.id]
    );

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        organizationId: user.organization_id,
      },
      tokens: {
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresIn: process.env.JWT_EXPIRES_IN || '8h',
      },
    });

  } catch (error) {
    logger.error('Login failed', error);
    res.status(500).json({
      error: 'Login failed',
      code: 'LOGIN_ERROR',
    });
  }
});

// Refresh token
router.post('/refresh', async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        error: 'Refresh token required',
        code: 'REFRESH_TOKEN_MISSING',
      });
    }

    const { userId } = verifyRefreshToken(refreshToken);

    // Get user data
    const userResult = await db.query(`
      SELECT id, email, role, organization_id, is_active
      FROM users
      WHERE id = $1 AND is_active = true
    `, [userId]);

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        error: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN',
      });
    }

    const user = userResult.rows[0];
    const permissions = await getUserPermissions(user.role);

    // Generate new access token
    const accessToken = generateToken({
      id: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organization_id,
      permissions,
    });

    logger.audit('Token refreshed', user.id, 'token_refresh');

    res.json({
      accessToken,
      tokenType: 'Bearer',
      expiresIn: process.env.JWT_EXPIRES_IN || '8h',
    });

  } catch (error) {
    logger.error('Token refresh failed', error);
    res.status(401).json({
      error: 'Invalid refresh token',
      code: 'INVALID_REFRESH_TOKEN',
    });
  }
});

// Logout (optional - mainly for audit trail)
router.post('/logout', async (req: Request, res: Response) => {
  try {
    // In a more complex implementation, you might maintain a blacklist of tokens
    // For now, we'll just log the logout event
    const authHeader = req.headers.authorization;
    if (authHeader) {
      // You could decode the token here to get user info for logging
      logger.info('User logged out');
    }

    res.json({
      message: 'Logged out successfully',
    });

  } catch (error) {
    logger.error('Logout error', error);
    res.status(500).json({
      error: 'Logout failed',
      code: 'LOGOUT_ERROR',
    });
  }
});

// Helper function to get user permissions based on role
async function getUserPermissions(role: string): Promise<string[]> {
  const rolePermissions: { [key: string]: string[] } = {
    admin: [
      'user:read', 'user:create', 'user:update', 'user:delete',
      'review:read', 'review:create', 'review:update', 'review:delete',
      'application:read', 'application:create', 'application:update', 'application:delete',
      'owasp:read', 'owasp:update',
      'dashboard:read', 'dashboard:admin',
    ],
    expert: [
      'review:read', 'review:create', 'review:update',
      'application:read',
      'owasp:read',
      'dashboard:read',
      'finding:create', 'finding:update',
    ],
    user: [
      'review:read', 'review:create',
      'application:read', 'application:create', 'application:update',
      'dashboard:read',
    ],
    viewer: [
      'review:read',
      'application:read',
      'dashboard:read',
    ],
  };

  return rolePermissions[role] || rolePermissions.viewer;
}

export default router; 