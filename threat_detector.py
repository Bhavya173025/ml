import joblib
import re
import requests
from urllib.parse import urlparse
import numpy as np

class ThreatDetector:
    def __init__(self, model_path='models/threat_model.pkl'):
        try:
            self.model = joblib.load(model_path)
            self.model_loaded = True
        except:
            self.model_loaded = False
            print("Model not found, using rule-based detection")
    
    def analyze_url(self, url):
        """Analyze URL for threats"""
        threats_detected = []
        confidence = 0.0
        
        # Rule-based detection
        if self.is_suspicious_url(url):
            threats_detected.append("Suspicious URL structure")
            confidence += 0.6
        
        if self.contains_malicious_keywords(url):
            threats_detected.append("Contains malicious keywords")
            confidence += 0.7
        
        if self.has_known_malicious_patterns(url):
            threats_detected.append("Known malicious patterns detected")
            confidence += 0.8
        
        # ML-based detection if model is available
        if self.model_loaded:
            try:
                ml_prediction, ml_confidence = self.model.predict(url)
                if ml_prediction == 1:
                    threats_detected.append("ML-based threat detection")
                    confidence = max(confidence, ml_confidence)
            except:
                pass
        
        # Determine threat level
        threat_level = "Low"
        if confidence > 0.8:
            threat_level = "Critical"
        elif confidence > 0.6:
            threat_level = "High"
        elif confidence > 0.4:
            threat_level = "Medium"
        
        return {
            "threat_level": threat_level,
            "confidence": min(confidence, 1.0),
            "threats_detected": threats_detected,
            "recommendation": self.get_recommendation(threat_level)
        }
    
    def is_suspicious_url(self, url):
        """Check for suspicious URL patterns"""
        suspicious_patterns = [
            r'\d+\.\d+\.\d+\.\d+',  # IP address in URL
            r'https?://[^/]*\.[^/]*\.[^/]*\.[^/]+',  # Multiple subdomains
            r'@',  # User info in URL
            r'\.(exe|zip|rar|js)$'  # Suspicious file extensions
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False
    
    def contains_malicious_keywords(self, url):
        """Check for malicious keywords in URL"""
        malicious_keywords = [
            'login', 'verify', 'account', 'banking', 'secure', 
            'update', 'password', 'confirm', 'validation'
        ]
        
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in malicious_keywords)
    
    def has_known_malicious_patterns(self, url):
        """Check for known malicious patterns"""
        patterns = [
            r'bit\.ly/',  # Short URLs
            r'tinyurl\.com/',
            r'goo\.gl/',
            r'redirect=',
            r'url='
        ]
        
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in patterns)
    
    def get_recommendation(self, threat_level):
        """Get recommendation based on threat level"""
        recommendations = {
            "Critical": "🚨 IMMEDIATE ACTION REQUIRED! Do not proceed. Block this URL immediately.",
            "High": "⚠️ HIGH RISK! Avoid accessing this URL. Report to security team.",
            "Medium": "🔶 Exercise caution. Verify the source before proceeding.",
            "Low": "✅ Appears safe, but remain vigilant."
        }
        return recommendations.get(threat_level, "No specific recommendation available.")
    
    def analyze_network_traffic(self, traffic_data):
        """Analyze network traffic patterns"""
        # Simplified network traffic analysis
        analysis = {
            "suspicious_connections": 0,
            "data_exfiltration_risk": "Low",
            "anomaly_detected": False
        }
        
        # Add your network analysis logic here
        return analysis
