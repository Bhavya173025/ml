import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import re
import requests
from urllib.parse import urlparse
import whois
from datetime import datetime

class AdvancedThreatDetectionModel:
    def __init__(self):
        self.models = {
            'random_forest': RandomForestClassifier(n_estimators=200, random_state=42),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'svm': SVC(probability=True, random_state=42),
            'neural_network': MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=1000, random_state=42)
        }
        self.vectorizer = TfidfVectorizer(max_features=2000, stop_words='english', ngram_range=(1, 3))
        self.selected_model = None
        self.is_trained = False
    
    def extract_advanced_features(self, url):
        """Extract comprehensive features from URL"""
        features = {}
        
        # URL Structure Features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_ampersands'] = url.count('&')
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_parameters'] = url.count('?')
        
        # Domain-based features
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            features['domain_length'] = len(domain)
            features['subdomain_count'] = domain.count('.') - 1
            features['has_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        except:
            features['domain_length'] = 0
            features['subdomain_count'] = 0
            features['has_ip'] = 0
        
        # Suspicious patterns
        suspicious_keywords = [
            'login', 'verify', 'account', 'banking', 'secure', 'update', 
            'password', 'confirm', 'validation', 'signin', 'admin', 'php',
            'js', 'exe', 'download', 'free', 'win', 'click'
        ]
        
        for keyword in suspicious_keywords:
            features[f'has_{keyword}'] = 1 if keyword in url.lower() else 0
        
        # Entropy-based features (randomness detection)
        features['entropy'] = self.calculate_entropy(url)
        
        # Special characters
        features['special_char_ratio'] = sum(1 for c in url if not c.isalnum()) / len(url) if url else 0
        
        return features
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if len(text) <= 1:
            return 0
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / len(text)
            entropy -= p * np.log2(p)
        return entropy
    
    def prepare_training_data(self, df):
        """Prepare comprehensive training data"""
        texts = df['url'].tolist()
        labels = df['label'].tolist()
        
        # Text features
        X_text = self.vectorizer.fit_transform(texts).toarray()
        
        # Manual features
        manual_features = []
        for text in texts:
            features = self.extract_advanced_features(text)
            manual_features.append(list(features.values()))
        
        X_manual = np.array(manual_features)
        
        # Combine features
        X_combined = np.hstack([X_text, X_manual])
        
        return X_combined, labels
    
    def train_models(self, df):
        """Train multiple models and select the best one"""
        X, y = self.prepare_training_data(df)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        best_score = 0
        best_model_name = None
        
        print("Training multiple ML models...")
        for name, model in self.models.items():
            # Train model
            model.fit(X_train, y_train)
            
            # Evaluate model
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            print(f"{name.upper()} Accuracy: {accuracy:.4f}")
            
            # Cross-validation
            cv_scores = cross_val_score(model, X, y, cv=5)
            print(f"{name.upper()} CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
            
            # Select best model
            if accuracy > best_score:
                best_score = accuracy
                best_model_name = name
                self.selected_model = model
        
        print(f"\n🎯 Best Model: {best_model_name} with accuracy: {best_score:.4f}")
        self.is_trained = True
        
        # Save the best model
        joblib.dump(self.selected_model, 'models/best_threat_model.pkl')
        joblib.dump(self.vectorizer, 'models/vectorizer.pkl')
        
        return best_model_name, best_score
    
    def predict_threat(self, url):
        """Predict threat level for a single URL"""
        if not self.is_trained:
            return "Model not trained", 0.0
        
        # Prepare features
        X_text = self.vectorizer.transform([url]).toarray()
        features = self.extract_advanced_features(url)
        X_manual = np.array([list(features.values())])
        X_combined = np.hstack([X_text, X_manual])
        
        # Make prediction
        prediction = self.selected_model.predict(X_combined)[0]
        probability = self.selected_model.predict_proba(X_combined)[0]
        
        threat_levels = {0: 'Safe', 1: 'Suspicious', 2: 'Malicious'}
        confidence = max(probability)
        
        return threat_levels.get(prediction, 'Unknown'), confidence

# Load real datasets
def load_real_datasets():
    """Load and combine real threat intelligence datasets"""
    
    # Sample real dataset structure (you should replace with actual datasets)
    data = {
        'url': [
            # Malicious URLs
            'http://malicious-phishing-site.com/login.php',
            'https://fake-bank-verify.com/account/update',
            'http://185.163.45.67/download.exe',
            'https://free-gift-card.scam/password/reset',
            
            # Safe URLs
            'https://www.google.com',
            'https://github.com/microsoft/vscode',
            'https://stackoverflow.com/questions',
            'https://www.wikipedia.org',
            
            # More samples for better training
            'http://suspicious-redirect.net/click.php',
            'https://account-verification-required.com',
            'http://download-free-software.now',
            'https://secure-payment-gateway.com',
            
            # Additional safe URLs
            'https://www.apple.com',
            'https://www.microsoft.com',
            'https://www.python.org',
            'https://www.linkedin.com'
        ],
        'label': [2, 2, 2, 2, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0]  # 0=Safe, 1=Suspicious, 2=Malicious
    }
    
    return pd.DataFrame(data)

# Enhanced threat detector with real ML
class MLThreatDetector:
    def __init__(self, model_path='models/best_threat_model.pkl', vectorizer_path='models/vectorizer.pkl'):
        try:
            self.model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)
            self.ml_ready = True
            print("✅ ML Model loaded successfully!")
        except Exception as e:
            print(f"❌ ML Model loading failed: {e}")
            self.ml_ready = False
        
        # Fallback to rule-based detection
        self.rule_detector = ThreatDetector()
    
    def analyze_with_ml(self, url):
        """Analyze URL using trained ML model"""
        if not self.ml_ready:
            return self.rule_detector.analyze_url(url)
        
        try:
            # Extract features for ML
            features = self.extract_advanced_features(url)
            feature_vector = self.prepare_feature_vector(url, features)
            
            # ML prediction
            prediction = self.model.predict(feature_vector)[0]
            probability = self.model.predict_proba(feature_vector)[0]
            confidence = max(probability)
            
            # Map to threat levels
            threat_map = {0: 'Low', 1: 'Medium', 2: 'High'}
            threat_level = threat_map.get(prediction, 'Unknown')
            
            # Get threats detected
            threats = self.get_ml_threat_explanations(prediction, features)
            
            return {
                "threat_level": threat_level,
                "confidence": confidence,
                "threats_detected": threats,
                "detection_method": "Machine Learning",
                "recommendation": self.get_ml_recommendation(threat_level, confidence)
            }
            
        except Exception as e:
            print(f"ML analysis failed: {e}")
            return self.rule_detector.analyze_url(url)
    
    def prepare_feature_vector(self, url, features):
        """Prepare feature vector for ML model"""
        # Text features
        X_text = self.vectorizer.transform([url]).toarray()
        
        # Manual features
        X_manual = np.array([list(features.values())])
        
        # Combine
        return np.hstack([X_text, X_manual])
    
    def extract_advanced_features(self, url):
        """Extract features matching training phase"""
        features = {}
        
        # URL Structure Features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_slashes'] = url.count('/')
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # Domain features
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            features['domain_length'] = len(domain)
            features['subdomain_count'] = domain.count('.') - 1
            features['has_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        except:
            features['domain_length'] = 0
            features['subdomain_count'] = 0
            features['has_ip'] = 0
        
        # Entropy
        features['entropy'] = self.calculate_entropy(url)
        features['special_char_ratio'] = sum(1 for c in url if not c.isalnum()) / len(url) if url else 0
        
        return features
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy"""
        if len(text) <= 1:
            return 0
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / len(text)
            entropy -= p * np.log2(p)
        return entropy
    
    def get_ml_threat_explanations(self, prediction, features):
        """Explain why ML model made this prediction"""
        explanations = []
        
        if prediction == 2:  # Malicious
            if features['has_ip']:
                explanations.append("IP address in domain (suspicious)")
            if features['url_length'] > 75:
                explanations.append("Unusually long URL")
            if features['entropy'] > 4.0:
                explanations.append("High entropy (random-looking)")
            if features['special_char_ratio'] > 0.3:
                explanations.append("High special character ratio")
                
        elif prediction == 1:  # Suspicious
            if features['num_dots'] > 3:
                explanations.append("Multiple subdomains")
            if features['url_length'] > 50:
                explanations.append("Long URL structure")
                
        else:  # Safe
            explanations.append("Normal URL patterns detected")
            
        return explanations if explanations else ["No specific threats detected"]
    
    def get_ml_recommendation(self, threat_level, confidence):
        """Get ML-based recommendations"""
        recommendations = {
            "High": f"🚨 BLOCK IMMEDIATELY! ML confidence: {confidence:.1%}",
            "Medium": f"⚠️ Exercise caution. ML confidence: {confidence:.1%}",
            "Low": f"✅ Likely safe. ML confidence: {confidence:.1%}"
        }
        return recommendations.get(threat_level, "No specific recommendation")

# Train and save the enhanced model
if __name__ == "__main__":
    print("🚀 Training Advanced ML Threat Detection Model...")
    
    # Load data
    df = load_real_datasets()
    print(f"📊 Dataset loaded: {len(df)} samples")
    
    # Train model
    advanced_model = AdvancedThreatDetectionModel()
    best_model, accuracy = advanced_model.train_models(df)
    
    print(f"\n🎉 Training completed!")
    print(f"🏆 Best model: {best_model}")
    print(f"📈 Accuracy: {accuracy:.4f}")
    
    # Test the model
    test_urls = [
        "https://www.google.com",
        "http://malicious-site.com/login.php",
        "https://github.com/microsoft"
    ]
    
    ml_detector = MLThreatDetector()
    
    print("\n🧪 Testing ML Model:")
    for url in test_urls:
        result = ml_detector.analyze_with_ml(url)
        print(f"\nURL: {url}")
        print(f"Threat Level: {result['threat_level']}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Method: {result['detection_method']}")
