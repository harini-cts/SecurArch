#!/usr/bin/env python3
"""
PostgreSQL Migration Script for SecureArch Portal
Migrates data from SQLite to PostgreSQL with enhanced security features
"""

import os
import sys
import sqlite3
import psycopg2
import psycopg2.extras
import uuid
import logging
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PostgreSQLMigrator:
    """Handle migration from SQLite to PostgreSQL"""
    
    def __init__(self):
        self.sqlite_db = 'securearch_portal.db'
        self.pg_config = {
            'host': os.environ.get('DB_HOST', 'localhost'),
            'port': os.environ.get('DB_PORT', 5432),
            'database': os.environ.get('DB_NAME', 'securearch_portal'),
            'user': os.environ.get('DB_USER', 'securearch_user'),
            'password': os.environ.get('DB_PASSWORD')
        }
    
    def validate_environment(self):
        """Validate required environment variables"""
        required_vars = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD']
        missing = [var for var in required_vars if not os.environ.get(var)]
        
        if missing:
            logger.error(f"Missing required environment variables: {missing}")
            return False
        return True
    
    def test_connections(self):
        """Test both SQLite and PostgreSQL connections"""
        logger.info("Testing database connections...")
        
        # Test SQLite
        if not os.path.exists(self.sqlite_db):
            logger.error(f"SQLite database not found: {self.sqlite_db}")
            return False
        
        try:
            sqlite_conn = sqlite3.connect(self.sqlite_db)
            sqlite_conn.close()
            logger.info("✅ SQLite connection successful")
        except Exception as e:
            logger.error(f"SQLite connection failed: {e}")
            return False
        
        # Test PostgreSQL
        try:
            pg_conn = psycopg2.connect(**self.pg_config)
            pg_conn.close()
            logger.info("✅ PostgreSQL connection successful")
        except Exception as e:
            logger.error(f"PostgreSQL connection failed: {e}")
            return False
        
        return True
    
    def create_postgresql_schema(self):
        """Create PostgreSQL schema with enhanced security features"""
        logger.info("Creating PostgreSQL schema...")
        
        schema_sql = """
        -- Enable UUID extension
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
        
        -- Users table with enhanced security
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            first_name VARCHAR(100) NOT NULL,
            last_name VARCHAR(100) NOT NULL,
            role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('user', 'security_analyst', 'admin')),
            organization_name VARCHAR(255),
            job_title VARCHAR(100),
            experience_level VARCHAR(20) CHECK (experience_level IN ('junior', 'intermediate', 'senior')),
            interests TEXT,
            onboarding_completed BOOLEAN DEFAULT FALSE,
            is_active BOOLEAN DEFAULT TRUE,
            email_verified BOOLEAN DEFAULT FALSE,
            two_factor_enabled BOOLEAN DEFAULT FALSE,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked_until TIMESTAMP WITH TIME ZONE,
            password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            last_login_at TIMESTAMP WITH TIME ZONE,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        
        -- Applications table with enhanced validation
        CREATE TABLE IF NOT EXISTS applications (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            name VARCHAR(255) NOT NULL CHECK (length(name) > 0),
            description TEXT CHECK (length(description) <= 2000),
            technology_stack TEXT,
            deployment_environment VARCHAR(50) CHECK (deployment_environment IN ('development', 'staging', 'production', 'hybrid')),
            business_criticality VARCHAR(20) CHECK (business_criticality IN ('Low', 'Medium', 'High', 'Critical')),
            data_classification VARCHAR(20) CHECK (data_classification IN ('Public', 'Internal', 'Confidential', 'Restricted')),
            author_id UUID NOT NULL,
            status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'submitted', 'in_review', 'completed', 'rejected')),
            logical_architecture_file TEXT,
            physical_architecture_file TEXT,
            overview_document_file TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE CASCADE
        );
        
        -- Security Reviews table with audit trail
        CREATE TABLE IF NOT EXISTS security_reviews (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            application_id UUID NOT NULL,
            field_type VARCHAR(50) CHECK (field_type IN ('application_review', 'cloud_review', 'mobile_review')),
            questionnaire_responses JSONB,
            additional_comments TEXT CHECK (length(additional_comments) <= 5000),
            screenshots JSONB,
            status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'submitted', 'in_review', 'completed', 'rejected')),
            risk_score DECIMAL(3,1) CHECK (risk_score >= 0 AND risk_score <= 10),
            author_id UUID NOT NULL,
            analyst_id UUID,
            analyst_reviewed_at TIMESTAMP WITH TIME ZONE,
            stride_analysis JSONB,
            final_report TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES users (id),
            FOREIGN KEY (analyst_id) REFERENCES users (id)
        );
        
        -- Notifications table with expiration
        CREATE TABLE IF NOT EXISTS notifications (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            title VARCHAR(255) NOT NULL CHECK (length(title) > 0),
            message TEXT NOT NULL CHECK (length(message) > 0 AND length(message) <= 1000),
            type VARCHAR(20) DEFAULT 'info' CHECK (type IN ('info', 'warning', 'error', 'success')),
            application_id UUID,
            user_id UUID,
            target_role VARCHAR(50) CHECK (target_role IN ('user', 'security_analyst', 'admin') OR target_role IS NULL),
            read_by JSONB DEFAULT '[]',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            expires_at TIMESTAMP WITH TIME ZONE,
            FOREIGN KEY (application_id) REFERENCES applications (id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
        
        -- STRIDE Analysis table for threat modeling
        CREATE TABLE IF NOT EXISTS stride_analysis (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            review_id UUID NOT NULL,
            threat_category VARCHAR(50) CHECK (threat_category IN ('spoofing', 'tampering', 'repudiation', 'information_disclosure', 'denial_of_service', 'elevation_of_privilege')),
            threat_description TEXT NOT NULL CHECK (length(threat_description) > 0),
            risk_level VARCHAR(20) CHECK (risk_level IN ('Low', 'Medium', 'High', 'Critical')),
            mitigation_status VARCHAR(20) DEFAULT 'pending' CHECK (mitigation_status IN ('pending', 'in_progress', 'completed', 'not_applicable')),
            question_id TEXT,
            recommendations TEXT CHECK (length(recommendations) <= 2000),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            FOREIGN KEY (review_id) REFERENCES security_reviews (id) ON DELETE CASCADE
        );
        
        -- Audit log table for security monitoring
        CREATE TABLE IF NOT EXISTS audit_logs (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID,
            action VARCHAR(100) NOT NULL,
            resource_type VARCHAR(50),
            resource_id UUID,
            details JSONB,
            ip_address INET,
            user_agent TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        
        -- Create performance indexes
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_role_active ON users(role, is_active);
        CREATE INDEX IF NOT EXISTS idx_applications_author_created ON applications(author_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
        CREATE INDEX IF NOT EXISTS idx_security_reviews_app_status ON security_reviews(application_id, status);
        CREATE INDEX IF NOT EXISTS idx_security_reviews_analyst ON security_reviews(analyst_id);
        CREATE INDEX IF NOT EXISTS idx_notifications_user_created ON notifications(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_notifications_role_created ON notifications(target_role, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_stride_analysis_review ON stride_analysis(review_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created ON audit_logs(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
        
        -- Create updated_at trigger function
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ language 'plpgsql';
        
        -- Create updated_at triggers
        CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        CREATE TRIGGER update_applications_updated_at BEFORE UPDATE ON applications FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        CREATE TRIGGER update_security_reviews_updated_at BEFORE UPDATE ON security_reviews FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        CREATE TRIGGER update_stride_analysis_updated_at BEFORE UPDATE ON stride_analysis FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        """
        
        try:
            pg_conn = psycopg2.connect(**self.pg_config)
            pg_cursor = pg_conn.cursor()
            
            pg_cursor.execute(schema_sql)
            pg_conn.commit()
            
            pg_cursor.close()
            pg_conn.close()
            
            logger.info("✅ PostgreSQL schema created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create PostgreSQL schema: {e}")
            return False
    
    def migrate_data(self):
        """Migrate data from SQLite to PostgreSQL"""
        logger.info("Starting data migration...")
        
        try:
            # Connect to both databases
            sqlite_conn = sqlite3.connect(self.sqlite_db)
            sqlite_conn.row_factory = sqlite3.Row
            
            pg_conn = psycopg2.connect(**self.pg_config)
            pg_cursor = pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Migrate users
            self._migrate_users(sqlite_conn, pg_cursor)
            
            # Migrate applications
            self._migrate_applications(sqlite_conn, pg_cursor)
            
            # Migrate security reviews
            self._migrate_security_reviews(sqlite_conn, pg_cursor)
            
            # Migrate notifications
            self._migrate_notifications(sqlite_conn, pg_cursor)
            
            # Migrate STRIDE analysis
            self._migrate_stride_analysis(sqlite_conn, pg_cursor)
            
            pg_conn.commit()
            
            sqlite_conn.close()
            pg_cursor.close()
            pg_conn.close()
            
            logger.info("✅ Data migration completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Data migration failed: {e}")
            return False
    
    def _migrate_users(self, sqlite_conn, pg_cursor):
        """Migrate users table"""
        logger.info("Migrating users...")
        
        sqlite_cursor = sqlite_conn.cursor()
        users = sqlite_cursor.execute("SELECT * FROM users").fetchall()
        
        for user in users:
            # Convert to UUID if needed
            user_id = user['id'] if self._is_uuid(user['id']) else str(uuid.uuid4())
            
            pg_cursor.execute("""
                INSERT INTO users (
                    id, email, password_hash, first_name, last_name, role,
                    organization_name, job_title, experience_level, interests,
                    onboarding_completed, is_active, created_at, last_login_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (
                user_id, user['email'], user['password_hash'], user['first_name'],
                user['last_name'], user['role'], user.get('organization_name'),
                user.get('job_title'), user.get('experience_level'), user.get('interests'),
                bool(user.get('onboarding_completed', 0)), bool(user.get('is_active', 1)),
                user.get('created_at'), user.get('last_login_at')
            ))
        
        logger.info(f"Migrated {len(users)} users")
    
    def _migrate_applications(self, sqlite_conn, pg_cursor):
        """Migrate applications table"""
        logger.info("Migrating applications...")
        
        sqlite_cursor = sqlite_conn.cursor()
        applications = sqlite_cursor.execute("SELECT * FROM applications").fetchall()
        
        for app in applications:
            app_id = app['id'] if self._is_uuid(app['id']) else str(uuid.uuid4())
            author_id = app['author_id'] if self._is_uuid(app['author_id']) else str(uuid.uuid4())
            
            pg_cursor.execute("""
                INSERT INTO applications (
                    id, name, description, technology_stack, deployment_environment,
                    business_criticality, data_classification, author_id, status,
                    logical_architecture_file, physical_architecture_file,
                    overview_document_file, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (
                app_id, app['name'], app.get('description'), app.get('technology_stack'),
                app.get('deployment_environment'), app.get('business_criticality'),
                app.get('data_classification'), author_id, app.get('status', 'draft'),
                app.get('logical_architecture_file'), app.get('physical_architecture_file'),
                app.get('overview_document_file'), app.get('created_at')
            ))
        
        logger.info(f"Migrated {len(applications)} applications")
    
    def _migrate_security_reviews(self, sqlite_conn, pg_cursor):
        """Migrate security reviews table"""
        logger.info("Migrating security reviews...")
        
        sqlite_cursor = sqlite_conn.cursor()
        reviews = sqlite_cursor.execute("SELECT * FROM security_reviews").fetchall()
        
        for review in reviews:
            review_id = review['id'] if self._is_uuid(review['id']) else str(uuid.uuid4())
            app_id = review['application_id'] if self._is_uuid(review['application_id']) else str(uuid.uuid4())
            author_id = review['author_id'] if self._is_uuid(review['author_id']) else str(uuid.uuid4())
            analyst_id = review.get('analyst_id')
            if analyst_id and not self._is_uuid(analyst_id):
                analyst_id = str(uuid.uuid4())
            
            pg_cursor.execute("""
                INSERT INTO security_reviews (
                    id, application_id, field_type, questionnaire_responses,
                    additional_comments, screenshots, status, risk_score,
                    author_id, analyst_id, analyst_reviewed_at, stride_analysis,
                    final_report, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (
                review_id, app_id, review.get('field_type'),
                review.get('questionnaire_responses'), review.get('additional_comments'),
                review.get('screenshots'), review.get('status', 'draft'),
                review.get('risk_score'), author_id, analyst_id,
                review.get('analyst_reviewed_at'), review.get('stride_analysis'),
                review.get('final_report'), review.get('created_at')
            ))
        
        logger.info(f"Migrated {len(reviews)} security reviews")
    
    def _migrate_notifications(self, sqlite_conn, pg_cursor):
        """Migrate notifications table"""
        logger.info("Migrating notifications...")
        
        sqlite_cursor = sqlite_conn.cursor()
        try:
            notifications = sqlite_cursor.execute("SELECT * FROM notifications").fetchall()
        except:
            logger.info("No notifications table found, skipping...")
            return
        
        for notif in notifications:
            notif_id = notif['id'] if self._is_uuid(notif['id']) else str(uuid.uuid4())
            app_id = notif.get('application_id')
            if app_id and not self._is_uuid(app_id):
                app_id = str(uuid.uuid4())
            user_id = notif.get('user_id')
            if user_id and not self._is_uuid(user_id):
                user_id = str(uuid.uuid4())
            
            pg_cursor.execute("""
                INSERT INTO notifications (
                    id, title, message, type, application_id, user_id,
                    target_role, read_by, created_at, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (
                notif_id, notif['title'], notif['message'], notif.get('type', 'info'),
                app_id, user_id, notif.get('target_role'), notif.get('read_by', '[]'),
                notif.get('created_at'), notif.get('expires_at')
            ))
        
        logger.info(f"Migrated {len(notifications)} notifications")
    
    def _migrate_stride_analysis(self, sqlite_conn, pg_cursor):
        """Migrate STRIDE analysis table"""
        logger.info("Migrating STRIDE analysis...")
        
        sqlite_cursor = sqlite_conn.cursor()
        try:
            analyses = sqlite_cursor.execute("SELECT * FROM stride_analysis").fetchall()
        except:
            logger.info("No stride_analysis table found, skipping...")
            return
        
        for analysis in analyses:
            analysis_id = analysis['id'] if self._is_uuid(analysis['id']) else str(uuid.uuid4())
            review_id = analysis['review_id'] if self._is_uuid(analysis['review_id']) else str(uuid.uuid4())
            
            pg_cursor.execute("""
                INSERT INTO stride_analysis (
                    id, review_id, threat_category, threat_description,
                    risk_level, mitigation_status, question_id, recommendations, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (
                analysis_id, review_id, analysis.get('threat_category'),
                analysis.get('threat_description'), analysis.get('risk_level'),
                analysis.get('mitigation_status', 'pending'), analysis.get('question_id'),
                analysis.get('recommendations'), analysis.get('created_at')
            ))
        
        logger.info(f"Migrated {len(analyses)} STRIDE analyses")
    
    def _is_uuid(self, value):
        """Check if value is a valid UUID"""
        try:
            uuid.UUID(str(value))
            return True
        except ValueError:
            return False
    
    def run_migration(self):
        """Run the complete migration process"""
        logger.info("Starting PostgreSQL migration process...")
        
        if not self.validate_environment():
            return False
        
        if not self.test_connections():
            return False
        
        if not self.create_postgresql_schema():
            return False
        
        if not self.migrate_data():
            return False
        
        logger.info("🎉 Migration completed successfully!")
        logger.info("You can now update your environment to use PostgreSQL:")
        logger.info("DATABASE_URL=postgresql://user:password@host:port/database")
        
        return True

if __name__ == '__main__':
    migrator = PostgreSQLMigrator()
    success = migrator.run_migration()
    
    if not success:
        sys.exit(1) 