from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import urllib.parse
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend connection

class RiskLevel(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"

@dataclass
class DetectionResult:
    url: str
    risk_level: RiskLevel
    confidence: float
    reasons: List[str]
    suggestions: List[str]
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'url': self.url,
            'risk_level': self.risk_level.value,
            'confidence': self.confidence,
            'reasons': self.reasons,
            'suggestions': self.suggestions
        }

class LinkSafetyDetector:
    def __init__(self):
        # Known dangerous domains (you'd expand this with real threat intel)
        self.dangerous_domains = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co'  # URL shorteners (higher risk)
        }
        
        # Suspicious patterns in URLs
        self.suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-z0-9-]+\.tk$',  # Free TLDs often used for scams
            r'[a-z0-9-]+\.ml$',
            r'[a-z0-9-]+\.ga$',
            r'[a-z0-9-]+\.cf$',
            r'urgent|act-now|limited-time|click-here|free-money|winner|congratulations',
            r'paypal|amazon|microsoft|apple|google.*login|secure.*update',  # Phishing attempts
            r'[0-9]{10,}',  # Long number sequences
            r'[a-z]{50,}',  # Extremely long random strings
        ]
        
        # Legitimate domains (whitelist)
        self.trusted_domains = {
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org',
            'amazon.com', 'netflix.com', 'spotify.com', 'apple.com', 'microsoft.com'
        }

    def analyze_url(self, url: str) -> DetectionResult:
        """Main analysis function that checks a URL for safety"""
        reasons = []
        suggestions = []
        risk_score = 0
        
        try:
            # Parse the URL
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            
            # Remove www. prefix for domain checking
            clean_domain = domain.replace('www.', '')
            
            # Check if it's a trusted domain
            if clean_domain in self.trusted_domains:
                return DetectionResult(
                    url=url,
                    risk_level=RiskLevel.SAFE,
                    confidence=0.95,
                    reasons=["Domain is in trusted whitelist"],
                    suggestions=["This appears to be a legitimate website"]
                )
            
            # Check for dangerous domains
            if clean_domain in self.dangerous_domains:
                risk_score += 30
                reasons.append(f"Uses URL shortener: {clean_domain}")
                suggestions.append("Be cautious with shortened URLs - check the destination first")
            
            # Check for suspicious patterns
            full_url = url.lower()
            for pattern in self.suspicious_patterns:
                if re.search(pattern, full_url):
                    risk_score += 15
                    reasons.append(f"Contains suspicious pattern")
            
            # Check for HTTPS
            if parsed.scheme != 'https':
                risk_score += 10
                reasons.append("Not using secure HTTPS connection")
                suggestions.append("Look for HTTPS (secure) versions of websites")
            
            # Check for suspicious TLDs
            if re.search(r'\.(tk|ml|ga|cf|click)$', clean_domain):
                risk_score += 25
                reasons.append("Uses suspicious top-level domain")
                suggestions.append("Be extra cautious with unusual domain extensions")
            
            # Check for IP addresses instead of domain names
            if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', clean_domain):
                risk_score += 35
                reasons.append("Uses IP address instead of domain name")
                suggestions.append("Legitimate websites typically use domain names, not IP addresses")
            
            # Check for excessive subdomains
            subdomain_count = len(domain.split('.')) - 2
            if subdomain_count > 2:
                risk_score += 20
                reasons.append(f"Has {subdomain_count} subdomains (potentially suspicious)")
                suggestions.append("Be wary of URLs with many subdomains")
            
            # Check for phishing keywords
            phishing_keywords = ['login', 'secure', 'update', 'verify', 'suspend', 'urgent']
            for keyword in phishing_keywords:
                if keyword in path or keyword in query:
                    risk_score += 15
                    reasons.append(f"Contains potential phishing keyword: {keyword}")
                    suggestions.append("Be cautious of urgent requests to login or update information")
            
            # Determine risk level based on score
            if risk_score >= 50:
                risk_level = RiskLevel.DANGEROUS
                confidence = min(0.95, 0.6 + (risk_score - 50) / 100)
                suggestions.append("🚨 High risk - strongly recommend avoiding this link")
            elif risk_score >= 25:
                risk_level = RiskLevel.SUSPICIOUS
                confidence = 0.7 + (risk_score - 25) / 100
                suggestions.append("⚠️ Medium risk - proceed with caution")
            else:
                risk_level = RiskLevel.SAFE
                confidence = 0.8 - risk_score / 100
                suggestions.append("✅ Appears relatively safe, but always stay vigilant")
            
            if not reasons:
                reasons.append("No obvious red flags detected")
            
            return DetectionResult(
                url=url,
                risk_level=risk_level,
                confidence=confidence,
                reasons=reasons,
                suggestions=suggestions
            )
            
        except Exception as e:
            return DetectionResult(
                url=url,
                risk_level=RiskLevel.SUSPICIOUS,
                confidence=0.5,
                reasons=[f"Error parsing URL: {str(e)}"],
                suggestions=["Unable to properly analyze this URL - proceed with caution"]
            )

# Initialize detector
detector = LinkSafetyDetector()

@app.route('/api/analyze', methods=['POST'])
def analyze_link():
    """API endpoint to analyze a single URL"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL is required',
                'message': 'Please provide a URL in the request body'
            }), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({
                'error': 'Empty URL',
                'message': 'URL cannot be empty'
            }), 400
        
        # Analyze the URL
        result = detector.analyze_url(url)
        
        # Return result as JSON
        return jsonify({
            'success': True,
            'data': result.to_dict()
        })
        
    except Exception as e:
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@app.route('/api/batch-analyze', methods=['POST'])
def batch_analyze_links():
    """API endpoint to analyze multiple URLs at once"""
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                'error': 'URLs are required',
                'message': 'Please provide a list of URLs in the request body'
            }), 400
        
        urls = data['urls']
        if not isinstance(urls, list):
            return jsonify({
                'error': 'Invalid format',
                'message': 'URLs must be provided as a list'
            }), 400
        
        if len(urls) > 50:  # Limit batch size
            return jsonify({
                'error': 'Too many URLs',
                'message': 'Maximum 50 URLs per batch request'
            }), 400
        
        # Analyze all URLs
        results = []
        for url in urls:
            if url.strip():  # Skip empty URLs
                result = detector.analyze_url(url.strip())
                results.append(result.to_dict())
        
        return jsonify({
            'success': True,
            'data': results,
            'count': len(results)
        })
        
    except Exception as e:
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'LinkGuard API',
        'version': '1.0.0'
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get some basic stats about the detector"""
    return jsonify({
        'trusted_domains_count': len(detector.trusted_domains),
        'dangerous_domains_count': len(detector.dangerous_domains),
        'detection_patterns_count': len(detector.suspicious_patterns),
        'supported_features': [
            'URL shortener detection',
            'Phishing pattern detection',
            'HTTPS verification',
            'IP address detection',
            'Suspicious TLD detection',
            'Trusted domain whitelist'
        ]
    })

if __name__ == '__main__':
    print("🚀 Starting LinkGuard API server...")
    print("📡 API Endpoints:")
    print("  POST /api/analyze - Analyze single URL")
    print("  POST /api/batch-analyze - Analyze multiple URLs")
    print("  GET /api/health - Health check")
    print("  GET /api/stats - Detector statistics")
    print("🌐 Server running on http://localhost:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)