"""
Dashboard Routes for SecureArch Portal
"""

from flask import Blueprint, jsonify

# Create Blueprint
dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/', methods=['GET'])
def get_dashboard():
    """Get dashboard data"""
    return jsonify({
        'message': 'Dashboard endpoint ready',
        'status': 'coming_soon',
        'features': [
            'Security Posture Overview',
            'Risk Metrics',
            'OWASP Compliance Status',
            'Recent Reviews',
            'Pending Applications'
        ]
    })

@dashboard_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    return jsonify({
        'message': 'Dashboard stats endpoint ready',
        'status': 'coming_soon'
    }) 