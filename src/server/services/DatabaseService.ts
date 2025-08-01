import { Pool, PoolClient, QueryResult } from 'pg';
import { Logger } from '../utils/Logger';

export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  ssl: boolean;
  max: number;
  idleTimeoutMillis: number;
  connectionTimeoutMillis: number;
}

export class DatabaseService {
  private static instance: DatabaseService;
  private pool: Pool;
  private logger: Logger;
  private isConnected: boolean = false;

  private constructor() {
    this.logger = new Logger('DatabaseService');
    this.pool = this.createPool();
  }

  public static getInstance(): DatabaseService {
    if (!DatabaseService.instance) {
      DatabaseService.instance = new DatabaseService();
    }
    return DatabaseService.instance;
  }

  public static async initialize(): Promise<void> {
    const instance = DatabaseService.getInstance();
    await instance.connect();
  }

  public static async close(): Promise<void> {
    const instance = DatabaseService.getInstance();
    await instance.disconnect();
  }

  private createPool(): Pool {
    const config: DatabaseConfig = {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      database: process.env.DB_NAME || 'securearch_portal',
      user: process.env.DB_USER || 'securearch_user',
      password: process.env.DB_PASSWORD || '',
      ssl: process.env.DB_SSL === 'true',
      max: 20, // Maximum number of clients in the pool
      idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
      connectionTimeoutMillis: 2000, // Return an error after 2 seconds if connection could not be established
    };

    this.logger.info(`Connecting to database: ${config.host}:${config.port}/${config.database}`);

    return new Pool({
      ...config,
      ssl: config.ssl ? { rejectUnauthorized: false } : false,
    });
  }

  public async connect(): Promise<void> {
    try {
      // Test connection
      const client = await this.pool.connect();
      await client.query('SELECT NOW()');
      client.release();

      this.isConnected = true;
      this.logger.info('Database connection established successfully');

      // Set up connection error handling
      this.pool.on('error', (err) => {
        this.logger.error('Unexpected error on idle client:', err);
        this.isConnected = false;
      });

    } catch (error) {
      this.isConnected = false;
      this.logger.error('Failed to connect to database:', error);
      throw new Error(`Database connection failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public async disconnect(): Promise<void> {
    try {
      await this.pool.end();
      this.isConnected = false;
      this.logger.info('Database connection closed');
    } catch (error) {
      this.logger.error('Error closing database connection:', error);
      throw error;
    }
  }

  public async query<T = any>(text: string, params?: any[]): Promise<QueryResult<T>> {
    if (!this.isConnected) {
      throw new Error('Database not connected');
    }

    const start = Date.now();
    try {
      const result = await this.pool.query<T>(text, params);
      const duration = Date.now() - start;
      
      if (process.env.NODE_ENV === 'development') {
        this.logger.debug(`Query executed in ${duration}ms: ${text.substring(0, 100)}...`);
      }
      
      return result;
    } catch (error) {
      this.logger.error('Database query error:', { 
        query: text.substring(0, 100),
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  public async getClient(): Promise<PoolClient> {
    if (!this.isConnected) {
      throw new Error('Database not connected');
    }
    return await this.pool.connect();
  }

  public async transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.getClient();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  public isHealthy(): boolean {
    return this.isConnected;
  }

  public async healthCheck(): Promise<{ status: string; latency: number; connections: number }> {
    const start = Date.now();
    try {
      await this.query('SELECT 1');
      const latency = Date.now() - start;
      
      return {
        status: 'healthy',
        latency,
        connections: this.pool.totalCount,
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        latency: Date.now() - start,
        connections: this.pool.totalCount,
      };
    }
  }

  // Utility methods for common operations
  public async findById<T = any>(table: string, id: string): Promise<T | null> {
    const result = await this.query<T>(`SELECT * FROM ${table} WHERE id = $1`, [id]);
    return result.rows[0] || null;
  }

  public async findMany<T = any>(
    table: string, 
    conditions: Record<string, any> = {},
    options: { limit?: number; offset?: number; orderBy?: string } = {}
  ): Promise<T[]> {
    let query = `SELECT * FROM ${table}`;
    const params: any[] = [];
    
    if (Object.keys(conditions).length > 0) {
      const whereClause = Object.keys(conditions)
        .map((key, index) => `${key} = $${index + 1}`)
        .join(' AND ');
      query += ` WHERE ${whereClause}`;
      params.push(...Object.values(conditions));
    }

    if (options.orderBy) {
      query += ` ORDER BY ${options.orderBy}`;
    }

    if (options.limit) {
      query += ` LIMIT $${params.length + 1}`;
      params.push(options.limit);
    }

    if (options.offset) {
      query += ` OFFSET $${params.length + 1}`;
      params.push(options.offset);
    }

    const result = await this.query<T>(query, params);
    return result.rows;
  }

  public async create<T = any>(table: string, data: Record<string, any>): Promise<T> {
    const keys = Object.keys(data);
    const values = Object.values(data);
    const placeholders = keys.map((_, index) => `$${index + 1}`).join(', ');
    const columns = keys.join(', ');

    const query = `
      INSERT INTO ${table} (${columns}) 
      VALUES (${placeholders}) 
      RETURNING *
    `;

    const result = await this.query<T>(query, values);
    return result.rows[0];
  }

  public async update<T = any>(
    table: string, 
    id: string, 
    data: Record<string, any>
  ): Promise<T | null> {
    const keys = Object.keys(data);
    const values = Object.values(data);
    const setClause = keys.map((key, index) => `${key} = $${index + 2}`).join(', ');

    const query = `
      UPDATE ${table} 
      SET ${setClause}, updated_at = NOW() 
      WHERE id = $1 
      RETURNING *
    `;

    const result = await this.query<T>(query, [id, ...values]);
    return result.rows[0] || null;
  }

  public async delete(table: string, id: string): Promise<boolean> {
    const result = await this.query(`DELETE FROM ${table} WHERE id = $1`, [id]);
    return result.rowCount !== null && result.rowCount > 0;
  }

  public async count(table: string, conditions: Record<string, any> = {}): Promise<number> {
    let query = `SELECT COUNT(*) as count FROM ${table}`;
    const params: any[] = [];
    
    if (Object.keys(conditions).length > 0) {
      const whereClause = Object.keys(conditions)
        .map((key, index) => `${key} = $${index + 1}`)
        .join(' AND ');
      query += ` WHERE ${whereClause}`;
      params.push(...Object.values(conditions));
    }

    const result = await this.query<{ count: string }>(query, params);
    return parseInt(result.rows[0].count, 10);
  }
}

// Export singleton instance
export const db = DatabaseService.getInstance(); 