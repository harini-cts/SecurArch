"""
Security Review Routes for SecureArch Portal
"""

from flask import Blueprint, jsonify

# Create Blueprint
reviews_bp = Blueprint('reviews', __name__)

@reviews_bp.route('/', methods=['GET'])
def list_reviews():
    """List all reviews"""
    return jsonify({
        'message': 'Reviews endpoint ready',
        'status': 'coming_soon'
    })

@reviews_bp.route('/', methods=['POST'])
def create_review():
    """Create a new review"""
    return jsonify({
        'message': 'Create review endpoint ready',
        'status': 'coming_soon'
    })

@reviews_bp.route('/<review_id>', methods=['GET'])
def get_review(review_id):
    """Get specific review"""
    return jsonify({
        'message': f'Get review {review_id} endpoint ready',
        'status': 'coming_soon'
    }) 