# Performance & Architecture Improvements

## 1. Database Optimization

### Current Issues:
- No connection pooling
- Inefficient queries (N+1 problem)
- Missing indexes
- No query optimization
- No caching layer

### Improvements:

```python
# Connection pooling and optimization
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
from redis import Redis
import functools

# Database connection with pooling
DATABASE_URL = "postgresql://..."
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=30,
    pool_pre_ping=True,
    pool_recycle=3600,
    echo=False  # Set to True for debugging
)

# Redis for caching
redis_client = Redis(
    host='localhost',
    port=6379,
    db=0,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=5
)

# Caching decorator
def cache_result(expiry=300):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key
            cache_key = f"{func.__name__}:{hash(str(args) + str(kwargs))}"
            
            # Try to get from cache
            cached_result = redis_client.get(cache_key)
            if cached_result:
                return json.loads(cached_result)
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            redis_client.setex(cache_key, expiry, json.dumps(result))
            return result
        return wrapper
    return decorator

# Optimized queries with eager loading
def get_applications_with_reviews(user_id, limit=10):
    """Optimized query to avoid N+1 problem"""
    query = """
    SELECT 
        a.*,
        sr.status as review_status,
        sr.created_at as review_created_at,
        COUNT(sr.id) as review_count
    FROM applications a
    LEFT JOIN security_reviews sr ON a.id = sr.application_id
    WHERE a.author_id = %s
    GROUP BY a.id, sr.status, sr.created_at
    ORDER BY a.created_at DESC
    LIMIT %s
    """
    return execute_query(query, (user_id, limit))

# Database indexes for performance
CREATE_INDEXES = [
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_applications_author_created ON applications(author_id, created_at DESC)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_reviews_app_status ON security_reviews(application_id, status)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notifications_user_created ON notifications(user_id, created_at DESC)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notifications_role_created ON notifications(target_role, created_at DESC)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_stride_analysis_review ON stride_analysis(review_id)",
]
```

## 2. Caching Strategy

### Multi-Level Caching:

```python
class CacheManager:
    """Multi-level caching with invalidation"""
    
    def __init__(self):
        self.redis = redis_client
        self.local_cache = {}  # In-memory cache for frequently accessed data
        self.cache_ttl = {
            'user_session': 3600,
            'application_list': 300,
            'notifications': 60,
            'dashboard_stats': 600,
            'owasp_data': 86400  # Static data cached for 24h
        }
    
    @cache_result(expiry=300)
    def get_user_applications(self, user_id):
        """Cache user applications list"""
        return get_applications_with_reviews(user_id)
    
    @cache_result(expiry=600)
    def get_dashboard_statistics(self, user_id):
        """Cache dashboard statistics"""
        return calculate_dashboard_stats(user_id)
    
    def invalidate_user_cache(self, user_id):
        """Invalidate all caches for a specific user"""
        patterns = [
            f"get_user_applications:*{user_id}*",
            f"get_dashboard_statistics:*{user_id}*",
            f"get_notifications_for_user:*{user_id}*"
        ]
        
        for pattern in patterns:
            keys = self.redis.keys(pattern)
            if keys:
                self.redis.delete(*keys)
    
    def invalidate_application_cache(self, app_id):
        """Invalidate caches when application changes"""
        # Get application owner to invalidate their caches
        app = get_application(app_id)
        if app:
            self.invalidate_user_cache(app['author_id'])
        
        # Invalidate analyst caches
        self.redis.delete(f"analyst_dashboard:*")
```

## 3. Asynchronous Processing

### Background Tasks with Celery:

```python
from celery import Celery
from celery.schedules import crontab

# Celery configuration
celery_app = Celery('securearch')
celery_app.config_from_object({
    'broker_url': 'redis://localhost:6379/1',
    'result_backend': 'redis://localhost:6379/2',
    'task_serializer': 'json',
    'accept_content': ['json'],
    'result_serializer': 'json',
    'timezone': 'UTC',
    'enable_utc': True,
    'beat_schedule': {
        'cleanup-expired-notifications': {
            'task': 'tasks.cleanup_expired_notifications',
            'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
        },
        'generate-sla-alerts': {
            'task': 'tasks.generate_sla_alerts',
            'schedule': crontab(minute='*/15'),  # Every 15 minutes
        },
        'update-analytics': {
            'task': 'tasks.update_analytics_data',
            'schedule': crontab(minute=0),  # Hourly
        }
    }
})

@celery_app.task
def process_document_upload(file_path, application_id):
    """Asynchronous document processing"""
    try:
        # Extract text from document
        extracted_text = extract_document_text(file_path)
        
        # Analyze for security patterns
        security_analysis = analyze_security_patterns(extracted_text)
        
        # Update application with analysis results
        update_application_analysis(application_id, security_analysis)
        
        # Send notification to user
        send_notification(
            application_id=application_id,
            title="Document Analysis Complete",
            message="Your uploaded document has been analyzed for security patterns."
        )
        
    except Exception as e:
        # Log error and notify user of failure
        logger.error(f"Document processing failed for {application_id}: {e}")
        send_notification(
            application_id=application_id,
            title="Document Analysis Failed",
            message="There was an error processing your uploaded document."
        )

@celery_app.task
def send_email_notification(user_email, subject, content):
    """Asynchronous email sending"""
    # Implementation for email sending
    pass

@celery_app.task
def cleanup_expired_notifications():
    """Clean up expired notifications"""
    expired_count = delete_expired_notifications()
    logger.info(f"Cleaned up {expired_count} expired notifications")

@celery_app.task
def generate_sla_alerts():
    """Generate and send SLA violation alerts"""
    sla_manager = SLAManager()
    alerts = sla_manager.generate_sla_alerts()
    
    for alert in alerts:
        # Send to relevant stakeholders
        send_sla_alert(alert)
```

## 4. API Response Optimization

### Efficient Data Serialization:

```python
from dataclasses import dataclass
from typing import List, Optional
import orjson  # Faster JSON serialization

@dataclass
class ApplicationResponse:
    """Optimized application response model"""
    id: str
    name: str
    status: str
    created_at: str
    review_count: int
    latest_review_status: Optional[str] = None
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'status': self.status,
            'created_at': self.created_at,
            'review_count': self.review_count,
            'latest_review_status': self.latest_review_status
        }

class OptimizedAPIResponse:
    """Optimized API response handling"""
    
    @staticmethod
    def jsonify_fast(data):
        """Fast JSON serialization with orjson"""
        return app.response_class(
            orjson.dumps(data),
            mimetype='application/json'
        )
    
    @staticmethod
    def paginate_response(query_result, page=1, per_page=20):
        """Efficient pagination"""
        total = len(query_result)
        start = (page - 1) * per_page
        end = start + per_page
        
        return {
            'data': query_result[start:end],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        }

# Optimized route example
@app.route('/api/applications')
@login_required
@cache_result(expiry=300)
def api_get_applications():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    
    # Efficient query with pagination at database level
    applications = get_user_applications_paginated(
        session['user_id'], 
        page=page, 
        per_page=per_page
    )
    
    # Convert to response models
    response_data = [
        ApplicationResponse(**app).to_dict() 
        for app in applications['data']
    ]
    
    return OptimizedAPIResponse.jsonify_fast({
        'success': True,
        'data': response_data,
        'pagination': applications['pagination']
    })
```

## 5. Frontend Performance

### Optimized JavaScript:

```javascript
// Efficient notification management
class OptimizedNotificationManager {
    constructor() {
        this.cache = new Map();
        this.updateQueue = [];
        this.batchUpdateTimer = null;
        this.init();
    }
    
    // Batch API calls to reduce server load
    batchMarkAsRead(notificationIds) {
        this.updateQueue.push(...notificationIds);
        
        if (this.batchUpdateTimer) {
            clearTimeout(this.batchUpdateTimer);
        }
        
        this.batchUpdateTimer = setTimeout(() => {
            this.processBatchUpdates();
        }, 1000); // Batch updates every second
    }
    
    async processBatchUpdates() {
        if (this.updateQueue.length === 0) return;
        
        const idsToUpdate = [...new Set(this.updateQueue)]; // Remove duplicates
        this.updateQueue = [];
        
        try {
            await fetch('/api/notifications/batch-read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ notification_ids: idsToUpdate })
            });
            
            // Update local cache
            idsToUpdate.forEach(id => {
                if (this.cache.has(id)) {
                    this.cache.get(id).is_read = true;
                }
            });
            
        } catch (error) {
            console.error('Batch update failed:', error);
        }
    }
    
    // Optimized rendering with virtual scrolling for large lists
    renderNotificationsList(notifications) {
        if (notifications.length > 50) {
            return this.renderVirtualizedList(notifications);
        }
        return this.renderStandardList(notifications);
    }
    
    // Debounced search to reduce API calls
    debounceSearch = this.debounce((query) => {
        this.performSearch(query);
    }, 300);
    
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
}
``` 