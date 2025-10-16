# app.py — Smart ML/DL Routing Based on URL Accessibility
import streamlit as st
import pandas as pd
import numpy as np
import pickle
import warnings
from pathlib import Path
import sys
import os
import re
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# Suppress warnings
warnings.filterwarnings("ignore")

# Add current directory to Python path for imports
current_dir = Path(__file__).resolve().parent
sys.path.append(str(current_dir))

# Try to import feature extraction module
try:
    from feature import FeatureExtraction
    FEATURE_EXTRACTION_AVAILABLE = True
except ImportError as e:
    st.warning(f"Feature extraction not available: {e}")
    FEATURE_EXTRACTION_AVAILABLE = False

# Page configuration
st.set_page_config(page_title="URL Phishing Detection", page_icon="🔒", layout="wide")
st.title("🔒 Advanced URL Phishing Detection System")
st.markdown("**Smart Detection: ML for accessible URLs | DL for inaccessible URLs**")

# =============================================================================
# MODEL LOADING
# =============================================================================
APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
MODEL_DIR = ROOT_DIR / "ML DL Trained Model"

@st.cache_resource
def load_models():
    """Load ML model and DL model from ML DL Trained Model directory"""
    models = {}
    loaded_models = []
    
    st.sidebar.info("🔍 Loading models from ML DL Trained Model...")
    
    try:
        if not MODEL_DIR.exists():
            st.sidebar.error(f"❌ Directory not found: {MODEL_DIR}")
            return models
        
        st.sidebar.info(f"📁 Model directory: {MODEL_DIR}")
        
        # List all files for debugging
        model_files = list(MODEL_DIR.glob("*"))
        st.sidebar.info(f"📄 Files found: {len(model_files)} files")
        
        # Load ML Model and Scaler
        ml_path = MODEL_DIR / "trained_ML_model.pkl"
        scaler_path = MODEL_DIR / "trained_ML_scaler.pkl"
        
        if ml_path.exists() and scaler_path.exists():
            try:
                with open(ml_path, 'rb') as f:
                    models['ml_model'] = pickle.load(f)
                with open(scaler_path, 'rb') as f:
                    models['scaler'] = pickle.load(f)
                loaded_models.append("ML Model")
                st.sidebar.success("✅ ML Model (30K Fresh Dataset)")
            except Exception as e:
                st.sidebar.error(f"❌ ML Model failed: {e}")
        else:
            st.sidebar.warning("⚠️ ML Model files not found")
        
        # Load DL Model
        dl_path = MODEL_DIR / "real_dataset_dl_model.h5"
        tokenizer_path = MODEL_DIR / "real_dataset_tokenizer.pkl"
        
        if dl_path.exists() and tokenizer_path.exists():
            try:
                import tensorflow as tf
                from tensorflow.keras.models import load_model
                
                models['dl_model'] = load_model(str(dl_path))
                
                with open(tokenizer_path, 'rb') as f:
                    models['tokenizer'] = pickle.load(f)
                
                loaded_models.append("DL Model")
                st.sidebar.success("✅ DL Model (CNN)")
            except Exception as e:
                st.sidebar.warning(f"⚠️ DL Model failed: {e}")
        else:
            st.sidebar.info("ℹ️ DL Model files not found")
        
        # Summary
        if loaded_models:
            st.sidebar.success(f"✅ {len(loaded_models)} models loaded")
        else:
            st.sidebar.error("❌ No models loaded")
            
    except Exception as e:
        st.sidebar.error(f"❌ Loading error: {e}")
    
    return models

# Load all models
models = load_models()

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def check_url_accessibility(url, timeout=10):
    """Check if URL is accessible"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        response = requests.head(
            url, 
            timeout=timeout,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0'},
            verify=False
        )
        return response.status_code < 400
    except requests.exceptions.Timeout:
        return "timeout"
    except:
        return False

def extract_features_with_timeout(url, timeout=10):
    """Extract features with timeout"""
    def extract_features():
        try:
            if not FEATURE_EXTRACTION_AVAILABLE:
                return None, "Feature extraction not available"
            
            extractor = FeatureExtraction(url)
            features = extractor.getFeaturesList()
            return features, None
        except Exception as e:
            return None, str(e)
    
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(extract_features)
        try:
            return future.result(timeout=timeout)
        except:
            return None, "Timeout"

def predict_with_dl(url, dl_model, tokenizer):
    """Predict using DL model"""
    try:
        from tensorflow.keras.preprocessing.sequence import pad_sequences
        
        url_seq = tokenizer.texts_to_sequences([url])
        url_pad = pad_sequences(url_seq, maxlen=200, padding='post')
        
        dl_prob = dl_model.predict(url_pad, verbose=0)[0][0]
        dl_pred = 1 if dl_prob > 0.5 else 0
        dl_conf = max(dl_prob, 1 - dl_prob)
        
        return int(dl_pred), float(dl_conf)
    except Exception as e:
        return 0, 0.5

# =============================================================================
# PREDICTION FUNCTIONS
# =============================================================================

def predict_single_url(url, timeout=10):
    """
    Single URL Prediction Logic:
    - Accessible URL → ML Model
    - Inaccessible URL → DL Model
    """
    result = {
        'url': url,
        'accessible': None,
        'timeout_occurred': False,
        'ml_prediction': None,
        'ml_confidence': None,
        'dl_prediction': None,
        'dl_confidence': None,
        'final_prediction': None,
        'final_confidence': None,
        'model_used': None,
        'error': None
    }
    
    try:
        # Check accessibility
        start_time = time.time()
        accessibility = check_url_accessibility(url, timeout)
        check_time = time.time() - start_time
        
        result['accessible'] = accessibility
        result['check_time'] = check_time
        
        ml_available = 'ml_model' in models and 'scaler' in models
        dl_available = 'dl_model' in models and 'tokenizer' in models
        
        # Handle timeout
        if accessibility == "timeout":
            result['timeout_occurred'] = True
            result['accessible'] = False
            
            # Timeout = Inaccessible → Use DL
            if dl_available:
                dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                result['dl_prediction'] = dl_pred
                result['dl_confidence'] = dl_conf
                result['final_prediction'] = dl_pred
                result['final_confidence'] = dl_conf
                result['model_used'] = 'DL (Timeout)'
            else:
                result['error'] = "DL model not available"
            
            return result
        
        # Accessible URL → Use ML
        if accessibility:
            if ml_available:
                try:
                    features, error = extract_features_with_timeout(url, timeout-2)
                    
                    if error or not features or len(features) != 30:
                        # Feature extraction failed → Fallback to DL
                        if dl_available:
                            dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                            result['dl_prediction'] = dl_pred
                            result['dl_confidence'] = dl_conf
                            result['final_prediction'] = dl_pred
                            result['final_confidence'] = dl_conf
                            result['model_used'] = 'DL (ML Fallback)'
                        else:
                            result['error'] = f"Feature extraction failed: {error}"
                    else:
                        # ML Prediction
                        features_array = np.array(features).reshape(1, -1)
                        features_scaled = models['scaler'].transform(features_array)
                        
                        if hasattr(models['ml_model'], "predict_proba"):
                            ml_proba = models['ml_model'].predict_proba(features_scaled)[0]
                            ml_pred = np.argmax(ml_proba)
                            ml_conf = max(ml_proba)
                        else:
                            ml_pred = models['ml_model'].predict(features_scaled)[0]
                            ml_conf = 0.75
                        
                        result['ml_prediction'] = int(ml_pred)
                        result['ml_confidence'] = float(ml_conf)
                        result['final_prediction'] = int(ml_pred)
                        result['final_confidence'] = float(ml_conf)
                        result['model_used'] = 'ML'
                        
                except Exception as e:
                    # ML failed → Fallback to DL
                    if dl_available:
                        dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                        result['dl_prediction'] = dl_pred
                        result['dl_confidence'] = dl_conf
                        result['final_prediction'] = dl_pred
                        result['final_confidence'] = dl_conf
                        result['model_used'] = 'DL (ML Error)'
                    else:
                        result['error'] = f"ML failed: {e}"
            else:
                result['error'] = "ML model not available"
        
        # Inaccessible URL → Use DL
        else:
            if dl_available:
                dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                result['dl_prediction'] = dl_pred
                result['dl_confidence'] = dl_conf
                result['final_prediction'] = dl_pred
                result['final_confidence'] = dl_conf
                result['model_used'] = 'DL'
            else:
                result['error'] = "DL model not available"
    
    except Exception as e:
        result['error'] = f"Prediction failed: {e}"
    
    return result

def predict_batch_url(url, use_ml=True, use_dl=True, timeout=10):
    """
    Batch Prediction Logic:
    - Uses both ML and DL models
    - Ensemble prediction (highest confidence wins)
    """
    result = {
        'url': url,
        'accessible': None,
        'timeout_occurred': False,
        'ml_prediction': None,
        'ml_confidence': None,
        'dl_prediction': None,
        'dl_confidence': None,
        'final_prediction': None,
        'final_confidence': None,
        'model_used': None,
        'error': None
    }
    
    try:
        # Check accessibility
        accessibility = check_url_accessibility(url, timeout)
        result['accessible'] = accessibility
        
        if accessibility == "timeout":
            result['timeout_occurred'] = True
            result['accessible'] = False
        
        ml_available = 'ml_model' in models and 'scaler' in models and use_ml
        dl_available = 'dl_model' in models and 'tokenizer' in models and use_dl
        
        # Try ML
        if ml_available and (accessibility or accessibility == "timeout"):
            try:
                features, error = extract_features_with_timeout(url, timeout-2)
                
                if not error and features and len(features) == 30:
                    features_array = np.array(features).reshape(1, -1)
                    features_scaled = models['scaler'].transform(features_array)
                    
                    if hasattr(models['ml_model'], "predict_proba"):
                        ml_proba = models['ml_model'].predict_proba(features_scaled)[0]
                        ml_pred = np.argmax(ml_proba)
                        ml_conf = max(ml_proba)
                    else:
                        ml_pred = models['ml_model'].predict(features_scaled)[0]
                        ml_conf = 0.75
                    
                    result['ml_prediction'] = int(ml_pred)
                    result['ml_confidence'] = float(ml_conf)
            except:
                pass
        
        # Try DL
        if dl_available:
            try:
                dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                result['dl_prediction'] = dl_pred
                result['dl_confidence'] = dl_conf
            except:
                pass
        
        # Determine final prediction
        if result['ml_prediction'] is not None and result['dl_prediction'] is not None:
            # Both available - use highest confidence
            if result['ml_confidence'] > result['dl_confidence']:
                result['final_prediction'] = result['ml_prediction']
                result['final_confidence'] = result['ml_confidence']
                result['model_used'] = 'ML (Ensemble)'
            else:
                result['final_prediction'] = result['dl_prediction']
                result['final_confidence'] = result['dl_confidence']
                result['model_used'] = 'DL (Ensemble)'
        
        elif result['ml_prediction'] is not None:
            result['final_prediction'] = result['ml_prediction']
            result['final_confidence'] = result['ml_confidence']
            result['model_used'] = 'ML Only'
        
        elif result['dl_prediction'] is not None:
            result['final_prediction'] = result['dl_prediction']
            result['final_confidence'] = result['dl_confidence']
            result['model_used'] = 'DL Only'
        
        else:
            result['error'] = "Both models failed"
    
    except Exception as e:
        result['error'] = f"Batch prediction failed: {e}"
    
    return result

# =============================================================================
# REGEX ANALYSIS
# =============================================================================

def analyze_url_with_regex(url):
    """Regex-based pattern analysis"""
    patterns = {
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'hex_encoded': r'%[0-9a-fA-F]{2}',
        'multiple_subdomains': r'([a-zA-Z0-9-]+\.){3,}',
        'suspicious_keywords': r'(login|verify|account|secure|update|banking|paypal)',
        'long_url': r'^.{50,}$',
        'shortening_service': r'(bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly)'
    }
    
    scores = {}
    total = 0
    
    for name, pattern in patterns.items():
        matches = re.findall(pattern, url.lower())
        score = len(matches) if matches else 0
        scores[name] = score
        total += score
    
    return {
        'scores': scores,
        'total': total,
        'risk': 'High' if total >= 4 else 'Medium' if total >= 2 else 'Low'
    }

# =============================================================================
# BATCH PROCESSING
# =============================================================================

def process_url_batch(url_data):
    """Process single URL for batch analysis"""
    idx, url, use_regex, use_ml, use_dl, timeout = url_data
    
    if not str(url).startswith(('http://', 'https://')):
        url = 'https://' + str(url)
    
    result = {
        'idx': idx,
        'url': url,
        'regex_pred': None,
        'regex_score': None,
        'ml_pred': None,
        'ml_conf': None,
        'dl_pred': None,
        'dl_conf': None,
        'final_pred': None,
        'final_conf': None,
        'accessible': None,
        'timeout': False,
        'model_used': None,
        'error': None
    }
    
    try:
        # Batch prediction
        pred_result = predict_batch_url(url, use_ml, use_dl, timeout)
        
        result.update({
            'ml_pred': pred_result.get('ml_prediction'),
            'ml_conf': pred_result.get('ml_confidence'),
            'dl_pred': pred_result.get('dl_prediction'),
            'dl_conf': pred_result.get('dl_confidence'),
            'final_pred': pred_result.get('final_prediction'),
            'final_conf': pred_result.get('final_confidence'),
            'accessible': pred_result.get('accessible'),
            'timeout': pred_result.get('timeout_occurred', False),
            'model_used': pred_result.get('model_used'),
            'error': pred_result.get('error')
        })
        
        # Regex
        if use_regex:
            regex = analyze_url_with_regex(url)
            result['regex_pred'] = 1 if regex['total'] >= 4 else 0
            result['regex_score'] = regex['total']
    
    except Exception as e:
        result['error'] = str(e)
    
    return result

# =============================================================================
# SIDEBAR CONFIGURATION
# =============================================================================

st.sidebar.header("Input Method")
input_mode = st.sidebar.radio(
    "Choose mode:",
    ["Single URL", "Batch Analysis"]
)

st.sidebar.header("Analysis Options")
use_regex = st.sidebar.checkbox("Enable Regex Analysis", value=True)

if input_mode == "Single URL":
    st.sidebar.info("**Single URL Logic:**\n✅ Accessible → ML Model\n❌ Inaccessible → DL Model")
    # Single mode always uses smart routing
    use_ml_batch = True
    use_dl_batch = True
else:
    st.sidebar.info("**Batch Logic:**\nUses both models for ensemble")
    use_ml_batch = st.sidebar.checkbox("Enable ML Model", value=True)
    use_dl_batch = st.sidebar.checkbox("Enable DL Model", value=True)

st.sidebar.header("Settings")
timeout_sec = st.sidebar.slider("Timeout (seconds)", 5, 30, 10)
max_workers = st.sidebar.slider("Parallel Workers", 1, 50, 10)

# Status
with st.sidebar:
    st.markdown("---")
    st.header("System Status")
    
    st.markdown("**Models:**")
    if 'ml_model' in models:
        st.success("✅ ML Model")
    else:
        st.error("❌ ML Model")
    
    if 'dl_model' in models:
        st.success("✅ DL Model")
    else:
        st.error("❌ DL Model")
    
    st.markdown("**Features:**")
    if FEATURE_EXTRACTION_AVAILABLE:
        st.success("✅ Feature Extraction")
    else:
        st.error("❌ Feature Extraction")

# =============================================================================
# SINGLE URL ANALYSIS
# =============================================================================

if input_mode == "Single URL":
    st.header("🔍 Single URL Analysis")
    st.info("**Smart Routing:** Accessible URLs → ML Model | Inaccessible URLs → DL Model")
    
    # Model status
    col1, col2 = st.columns(2)
    with col1:
        if 'ml_model' in models:
            st.success("✅ ML Ready (accessible URLs)")
        else:
            st.error("❌ ML Not Loaded")
    
    with col2:
        if 'dl_model' in models:
            st.success("✅ DL Ready (inaccessible URLs)")
        else:
            st.error("❌ DL Not Loaded")
    
    if 'ml_model' not in models and 'dl_model' not in models:
        st.error("❌ No models available. Cannot analyze.")
        st.stop()
    
    url_input = st.text_input("Enter URL:", placeholder="https://example.com")
    
    col1, col2 = st.columns(2)
    with col1:
        analyze_btn = st.button("🔍 Analyze URL", type="primary")
    with col2:
        quick_btn = st.button("⚡ Quick (5s)")
    
    if analyze_btn or quick_btn:
        if not url_input.strip():
            st.error("Please enter a URL")
            st.stop()
        
        timeout = 5 if quick_btn else timeout_sec
        
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input
        
        with st.spinner(f"Analyzing... (timeout: {timeout}s)"):
            result = predict_single_url(url_input, timeout)
        
        st.subheader("📊 Results")
        
        if result.get('error') and result.get('final_prediction') is None:
            st.error(f"❌ {result['error']}")
        else:
            # Results
            col1, col2, col3 = st.columns(3)
            
            with col1:
                pred = result.get('final_prediction', 0)
                conf = result.get('final_confidence', 0)
                label = "🛑 PHISHING" if pred == 1 else "✅ LEGITIMATE"
                st.metric("Prediction", label, f"{conf:.1%}")
            
            with col2:
                if result.get('timeout_occurred'):
                    status = "⏰ Timeout"
                elif result.get('accessible'):
                    status = "✅ Accessible"
                else:
                    status = "❌ Inaccessible"
                st.metric("URL Status", status)
            
            with col3:
                model = result.get('model_used', 'Unknown')
                st.metric("Model", model)
            
            # Explanation
            if result.get('accessible'):
                st.success("✅ URL is **accessible** → Used **ML Model** (feature-based)")
            else:
                st.info("❌ URL is **inaccessible** → Used **DL Model** (character-based)")
            
            # Details
            with st.expander("🔍 Detailed Analysis"):
                if result.get('ml_prediction') is not None:
                    ml_label = "🛑 PHISHING" if result['ml_prediction'] == 1 else "✅ LEGITIMATE"
                    st.write(f"**ML:** {ml_label} ({result['ml_confidence']:.1%})")
                
                if result.get('dl_prediction') is not None:
                    dl_label = "🛑 PHISHING" if result['dl_prediction'] == 1 else "✅ LEGITIMATE"
                    st.write(f"**DL:** {dl_label} ({result['dl_confidence']:.1%})")
                
                if use_regex:
                    regex = analyze_url_with_regex(url_input)
                    st.write(f"**Regex:** Score {regex['total']} ({regex['risk']} risk)")
                    
                    if regex['total'] > 0:
                        st.write("**Patterns:**")
                        for name, score in regex['scores'].items():
                            if score > 0:
                                st.write(f"  - {name.replace('_', ' ').title()}: {score}")
                
                if result.get('check_time'):
                    st.write(f"**Check time:** {result['check_time']:.2f}s")
                
                if result.get('error'):
                    st.warning(f"⚠️ {result['error']}")
            
            # Confidence warning
            conf = result.get('final_confidence', 0)
            if conf and conf < 0.6:
                st.warning("⚠️ Low confidence - manual review recommended")
            elif conf and conf > 0.9:
                st.success("✅ High confidence prediction")

# =============================================================================
# BATCH ANALYSIS
# =============================================================================

elif input_mode == "Batch Analysis":
    st.header("📊 Batch URL Analysis")
    st.info("**Ensemble Mode:** Uses both ML and DL models together")
    
    if 'ml_model' not in models and 'dl_model' not in models:
        st.error("❌ No models available")
        st.stop()
    
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    
    if uploaded:
        df = pd.read_csv(uploaded)
        df.columns = df.columns.str.strip()
        
        st.write(f"**Preview:** {len(df)} rows")
        st.dataframe(df.head())
        
        # Find URL column
        url_cols = [c for c in df.columns if c.lower() in {"url", "website", "link"}]
        if not url_cols:
            st.error("❌ No URL column found")
            st.stop()
        
        url_col = url_cols[0]
        st.success(f"📌 URL column: '{url_col}'")
        
        if st.button("🚀 Run Batch Analysis", type="primary"):
            try:
                st.info(f"Processing {len(df)} URLs...")
                
                url_data = [(i, row[url_col], use_regex, use_ml_batch, use_dl_batch, timeout_sec) 
                           for i, row in df.iterrows()]
                
                results = {}
                progress = st.progress(0)
                status = st.empty()
                
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = [executor.submit(process_url_batch, data) for data in url_data]
                    
                    for i, future in enumerate(as_completed(futures)):
                        res = future.result()
                        results[res['idx']] = res
                        
                        progress.progress((i + 1) / len(df))
                        status.text(f"{i+1}/{len(df)} URLs")
                
                progress.empty()
                status.empty()
                
                # Build results dataframe
                results_df = df.copy()
                
                for idx in range(len(df)):
                    if idx in results:
                        r = results[idx]
                        if use_regex:
                            results_df.at[idx, 'Regex_Pred'] = r.get('regex_pred', 0)
                            results_df.at[idx, 'Regex_Score'] = r.get('regex_score', 0)
                        if use_ml_batch:
                            results_df.at[idx, 'ML_Pred'] = r.get('ml_pred', 0)
                            results_df.at[idx, 'ML_Conf'] = r.get('ml_conf', 0)
                        if use_dl_batch:
                            results_df.at[idx, 'DL_Pred'] = r.get('dl_pred', 0)
                            results_df.at[idx, 'DL_Conf'] = r.get('dl_conf', 0)
                        
                        results_df.at[idx, 'Final_Pred'] = r.get('final_pred', 0)
                        results_df.at[idx, 'Final_Conf'] = r.get('final_conf', 0)
                        results_df.at[idx, 'Accessible'] = r.get('accessible', False)
                        results_df.at[idx, 'Timeout'] = r.get('timeout', False)
                        results_df.at[idx, 'Model_Used'] = r.get('model_used', 'unknown')
                
                st.success("✅ Complete!")
                
                # Summary
                st.subheader("📊 Summary")
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total", len(results_df))
                with col2:
                    timeouts = int(results_df['Timeout'].sum())
                    st.metric("Timeouts", timeouts)
                with col3:
                    phishing = int(results_df['Final_Pred'].sum())
                    st.metric("Phishing", phishing)
                with col4:
                    avg_conf = results_df['Final_Conf'].mean()
                    st.metric("Avg Confidence", f"{avg_conf:.1%}")
                
                # Model usage
                if 'Model_Used' in results_df.columns:
                    st.subheader("🔧 Model Distribution")
                    counts = results_df['Model_Used'].value_counts()
                    for model, count in counts.items():
                        st.write(f"- **{model}**: {count} URLs")
                
                # Download
                st.subheader("📥 Download")
                csv = results_df.to_csv(index=False)
                st.download_button(
                    "📥 Download Results",
                    csv,
                    "analysis_results.csv",
                    "text/csv"
                )
                
                # Sample
                st.subheader("🔍 Sample")
                cols = [url_col, 'Final_Pred', 'Final_Conf', 'Model_Used']
                if 'Accessible' in results_df.columns:
                    cols.append('Accessible')
                
                sample = results_df[cols].copy()
                sample['Final_Pred'] = sample['Final_Pred'].map({0: 'Legit', 1: 'Phishing'})
                sample['Final_Conf'] = sample['Final_Conf'].apply(lambda x: f"{x:.1%}" if pd.notna(x) else "N/A")
                
                st.dataframe(sample.head(20))
                
                # Phishing URLs
                phishing_df = results_df[results_df['Final_Pred'] == 1]
                if len(phishing_df) > 0:
                    st.subheader("🚨 Phishing URLs")
                    st.warning(f"{len(phishing_df)} detected")
                    
                    phish_sample = phishing_df[[url_col, 'Final_Conf', 'Model_Used']].copy()
                    phish_sample['Final_Conf'] = phish_sample['Final_Conf'].apply(lambda x: f"{x:.1%}" if pd.notna(x) else "N/A")
                    st.dataframe(phish_sample.head(10))
            
            except Exception as e:
                st.error(f"❌ Error: {e}")
                import traceback
                st.code(traceback.format_exc())

# =============================================================================
# FOOTER
# =============================================================================

st.markdown("---")
st.markdown("**Advanced Phishing Detection System**")
st.caption("Smart ML/DL Routing • ML for accessible URLs • DL for inaccessible URLs • Trained on 30K+ fresh URLs")
