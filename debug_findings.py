import sqlite3
import json

# Connect to database
conn = sqlite3.connect('securearch_portal.db')
cursor = conn.cursor()

print("=== Debugging Security Review Results Findings ===")

# Get the most recent review
cursor.execute('''
    SELECT sr.id, a.name, a.id as app_id, sr.status
    FROM security_reviews sr 
    JOIN applications a ON sr.application_id = a.id 
    ORDER BY sr.created_at DESC 
    LIMIT 5
''')

reviews = cursor.fetchall()
print(f"\nRecent Reviews:")
for review_id, app_name, app_id, status in reviews:
    print(f"  Review {review_id}: {app_name} (App ID: {app_id}) - Status: {status}")
    
    # Get findings for this review
    cursor.execute('''
        SELECT threat_category, threat_description, risk_level, question_id
        FROM stride_analysis 
        WHERE review_id = ?
    ''', (review_id,))
    
    findings = cursor.fetchall()
    print(f"    Findings: {len(findings)}")
    for finding in findings:
        category, desc, risk, qid = finding
        print(f"      - {risk} Risk: {category} (Q{qid})")
        print(f"        Description: {desc[:50]}..." if desc else "        No description")
    print()

conn.close() 