if not MODEL_DIR.exists():
            st.sidebar.error(f"❌ Directory not found: {MODEL_DIR}")
            return models
        
        st.sidebar.info(f"📁 Model directory: {MODEL_DIR}")
        
        # List all files in the directory for debugging
        model_files = list(MODEL_DIR.glob("*"))
        st.sidebar.info(f"📄 Files found: {[f.name for f in model_files]}")
        
        # Load ML Model and Scaler - UPDATED FILENAMES
        ml_path = MODEL_DIR / "trained_ML_model.pkl"
        scaler_path = MODEL_DIR / "trained_ML_scaler.pkl"
        
        if ml_path.exists() and scaler_path.exists():
            try:
                with open(ml_path, 'rb') as f:
                    models['ml_model'] = pickle.load(f)
                with open(scaler_path, 'rb') as f:
                    models['scaler'] = pickle.load(f)
                loaded_models.append("ML Model")
                st.sidebar.success("✅ ML Model (Fresh 30K Dataset) Loaded")
                
                # Display model info
                st.sidebar.info(f"📊 Model Type: {type(models['ml_model']).__name__}")
            except Exception as e:
                st.sidebar.error(f"❌ ML Model loading failed: {e}")
        else:
            missing = []
            if not ml_path.exists():
                missing.append("trained_ML_model.pkl")
            if not scaler_path.exists():
                missing.append("trained_ML_scaler.pkl")
            st.sidebar.error(f"❌ ML Model files missing: {', '.join(missing)}")
        
        # Load DL Model if available
        dl_path = MODEL_DIR / "real_dataset_dl_model.h5"
        tokenizer_path = MODEL_DIR / "real_dataset_tokenizer.pkl"
        
        if dl_path.exists() and tokenizer_path.exists():
            try:
                import tensorflow as tf
                from tensorflow.keras.models import load_model
                
                # Load DL model
                models['dl_model'] = load_model(str(dl_path))
                
                # Load tokenizer
                with open(tokenizer_path, 'rb') as f:
                    models['tokenizer'] = pickle.load(f)
                
                loaded_models.append("DL Model")
                st.sidebar.success("✅ DL Model Loaded")
                
            except Exception as e:
                st.sidebar.warning(f"⚠️ DL Model loading failed: {e}")
        else:
            st.sidebar.info("ℹ️ DL Model not found (optional)")
        
        # Summary
        if loaded_models:
            st.sidebar.success(f"✅ Loaded {len(loaded_models)} models: {', '.join(loaded_models)}")
        else:
            st.sidebar.error("❌ No models were successfully loaded")
            
    except Exception as e:
        st.sidebar.error(f"❌ Model loading system error: {e}")
    
    return models

# Load all models
models = load_models()

# -----------------------------------------------------------------------------
# Timeout Functions
# -----------------------------------------------------------------------------
def check_url_accessibility(url, timeout=10):
    """Check if URL is accessible within timeout period"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        response = requests.head(
            url, 
            timeout=timeout,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
            verify=False
        )
        return response.status_code < 400
    except requests.exceptions.Timeout:
        return "timeout"
    except Exception:
        return False

def extract_features_with_timeout(url, timeout=10):
    """Extract features with timeout protection"""
    def extract_features():
        try:
            if not FEATURE_EXTRACTION_AVAILABLE:
                return None, "Feature extraction not available"
            
            extractor = FeatureExtraction(url)
            features = extractor.getFeaturesList()
            return features, None
        except Exception as e:
            return None, str(e)
    
    # Run with timeout
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(extract_features)
        try:
            result = future.result(timeout=timeout)
            return result
        except Exception:
            return None, "Feature extraction timeout"

# -----------------------------------------------------------------------------
# Enhanced Prediction Function
# -----------------------------------------------------------------------------
def enhanced_url_prediction(url, use_ml=True, use_dl=False, timeout=10, is_single_analysis=False):
    """
    Enhanced prediction with timeout handling
    
    LOGIC FOR SINGLE URL ANALYSIS:
    - If URL is accessible → Use ML Model
    - If URL is NOT accessible → Use DL Model
    
    LOGIC FOR BATCH ANALYSIS:
    - Always use both ML and DL models for comprehensive analysis
    """
    results = {
        'url': url,
        'accessible': None,
        'timeout_occurred': False,
        'ml_prediction': None,
        'ml_confidence': None,
        'dl_prediction': None,
        'dl_confidence': None,
        'final_prediction': None,
        'final_confidence': None,
        'method_used': None,
        'error': None
    }
    
    try:
        # Step 1: Check URL accessibility with timeout
        start_time = time.time()
        accessibility = check_url_accessibility(url, timeout)
        check_time = time.time() - start_time
        
        results['accessible'] = accessibility
        results['accessibility_check_time'] = check_time
        
        # Check if models are available
        dl_available = 'dl_model' in models and 'tokenizer' in models
        ml_available = 'ml_model' in models and 'scaler' in models
        
        if not ml_available and not dl_available:
            results['error'] = "No models available"
            return results
        
        # =====================================================================
        # SINGLE URL ANALYSIS MODE
        # =====================================================================
        if is_single_analysis:
            if accessibility == "timeout":
                results['timeout_occurred'] = True
                results['accessible'] = False
                # Timeout = Not accessible → Use DL Model
                if dl_available:
                    results['method_used'] = 'dl_single_timeout'
                    dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                    results['dl_prediction'] = dl_pred
                    results['dl_confidence'] = dl_conf
                    results['final_prediction'] = dl_pred
                    results['final_confidence'] = dl_conf
                else:
                    results['error'] = "DL model not available for inaccessible URL"
                return results
            
            elif accessibility:  # URL is accessible → Use ML Model
                if ml_available:
                    try:
                        # Extract features with timeout
                        features, error = extract_features_with_timeout(url, timeout-2)
                        
                        if error:
                            # If feature extraction fails, fallback to DL
                            if dl_available:
                                results['method_used'] = 'dl_single_fallback'
                                dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                                results['dl_prediction'] = dl_pred
                                results['dl_confidence'] = dl_conf
                                results['final_prediction'] = dl_pred
                                results['final_confidence'] = dl_conf
                            else:
                                results['error'] = f"Feature extraction failed: {error}"
                        elif features and len(features) == 30:
                            # Make ML prediction
                            features_array = np.array(features).reshape(1, -1)
                            features_scaled = models['scaler'].transform(features_array)
                            
                            if hasattr(models['ml_model'], "predict_proba"):
                                ml_proba = models['ml_model'].predict_proba(features_scaled)[0]
                                ml_pred = np.argmax(ml_proba)
                                ml_conf = max(ml_proba)
                            else:
                                ml_pred = models['ml_model'].predict(features_scaled)[0]
                                ml_conf = 0.75
                            
                            results['ml_prediction'] = int(ml_pred)
                            results['ml_confidence'] = float(ml_conf)
                            results['method_used'] = 'ml_single_accessible'
                            results['final_prediction'] = int(ml_pred)
                            results['final_confidence'] = float(ml_conf)
                        else:
                            results['error'] = "Invalid feature extraction (expected 30 features)"
                                
                    except Exception as e:
                        # Fallback to DL if ML fails
                        if dl_available:
                            results['method_used'] = 'dl_single_fallback'
                            dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                            results['dl_prediction'] = dl_pred
                            results['dl_confidence'] = dl_conf
                            results['final_prediction'] = dl_pred
                            results['final_confidence'] = dl_conf
                        else:
                            results['error'] = f"ML prediction failed: {e}"
                else:
                    results['error'] = "ML model not available for accessible URL"
            
            else:  # URL not accessible → Use DL Model
                if dl_available:
                    results['method_used'] = 'dl_single_inaccessible'
                    dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                    results['dl_prediction'] = dl_pred
                    results['dl_confidence'] = dl_conf
                    results['final_prediction'] = dl_pred
                    results['final_confidence'] = dl_conf
                else:
                    results['error'] = "DL model not available for inaccessible URL"
        
        # =====================================================================
        # BATCH ANALYSIS MODE - Use both models
        # =====================================================================
        else:
            if accessibility == "timeout":
                results['timeout_occurred'] = True
                results['accessible'] = False
            
            # Try ML model if URL is accessible or timeout
            if (accessibility or accessibility == "timeout") and ml_available:
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
                        
                        results['ml_prediction'] = int(ml_pred)
                        results['ml_confidence'] = float(ml_conf)
                except Exception as e:
                    pass  # ML failed, will use DL
            
            # Try DL model
            if dl_available:
                try:
                    dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                    results['dl_prediction'] = dl_pred
                    results['dl_confidence'] = dl_conf
                except Exception as e:
                    pass  # DL failed
            
            # Determine final prediction for batch mode
            if results['ml_prediction'] is not None and results['dl_prediction'] is not None:
                # Both models available - use ensemble
                ml_conf = results['ml_confidence']
                dl_conf = results['dl_confidence']
                
                # Weighted ensemble based on confidence
                if ml_conf > dl_conf:
                    results['final_prediction'] = results['ml_prediction']
                    results['final_confidence'] = ml_conf
                    results['method_used'] = 'batch_ml_primary'
                else:
                    results['final_prediction'] = results['dl_prediction']
                    results['final_confidence'] = dl_conf
                    results['method_used'] = 'batch_dl_primary'
            
            elif results['ml_prediction'] is not None:
                # Only ML available
                results['final_prediction'] = results['ml_prediction']
                results['final_confidence'] = results['ml_confidence']
                results['method_used'] = 'batch_ml_only'
            
            elif results['dl_prediction'] is not None:
                # Only DL available
                results['final_prediction'] = results['dl_prediction']
                results['final_confidence'] = results['dl_confidence']
                results['method_used'] = 'batch_dl_only'
            
            else:
                results['error'] = "Both ML and DL predictions failed"
    
    except Exception as e:
        results['error'] = f"Prediction failed: {e}"
    
    return results

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
        st.warning(f"DL prediction error: {e}")
        return 0, 0.5  # Default to benign with low confidence

# -----------------------------------------------------------------------------
# Regex Analysis Functions
# -----------------------------------------------------------------------------
def analyze_url_with_regex(url):
    """Basic regex analysis for URL patterns"""
    suspicious_patterns = {
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'hex_encoded': r'%[0-9a-fA-F]{2}',
        'multiple_subdomains': r'([a-zA-Z0-9-]+\.){3,}',
        'suspicious_keywords': r'(login|verify|account|secure|update|banking|paypal)',
        'long_url': r'^.{50,}# app.py — Updated for New Model Structure
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
st.markdown("**Detect malicious URLs using Fresh ML Model (30K URLs)**")

# -----------------------------------------------------------------------------
# Load Models - UPDATED FOR NEW STRUCTURE
# -----------------------------------------------------------------------------
APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent

# Updated model paths - looking in ML DL Trained Model directory
MODEL_DIR = ROOT_DIR / "ML DL Trained Model"

@st.cache_resource
def load_models():
    """Load ML model and scaler from ML DL Trained Model directory"""
    models = {}
    loaded_models = []
    
    st.sidebar.info("🔍 Loading models from ML DL Trained Model...")
    
    try:
        # Check if ML DL Trained Model directory exists
        ,
        'shortening_service': r'(bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly)'
    }
    
    scores = {}
    total_score = 0
    
    for pattern_name, pattern in suspicious_patterns.items():
        matches = re.findall(pattern, url.lower())
        if matches:
            scores[pattern_name] = len(matches)
            total_score += len(matches)
        else:
            scores[pattern_name] = 0
    
    return {
        'scores': scores,
        'total_score': total_score,
        'risk_level': 'High' if total_score >= 4 else 'Medium' if total_score >= 2 else 'Low'
    }

def get_regex_prediction(url):
    """Get regex-based prediction"""
    analysis = analyze_url_with_regex(url)
    return 1 if analysis['total_score'] >= 4 else 0

# -----------------------------------------------------------------------------
# Single URL Processing
# -----------------------------------------------------------------------------
def process_single_url_enhanced(url_data):
    """Enhanced single URL processing for BATCH mode"""
    idx, url, use_regex, use_ml, use_dl, timeout = url_data
    
    # Add protocol if missing
    if not str(url).startswith(('http://', 'https://')):
        url = 'https://' + str(url)
    
    result = {
        'idx': idx,
        'url': url,
        'regex_pred': None,
        'regex_score': None,
        'ml_pred': None,
        'ml_confidence': None,
        'dl_pred': None,
        'dl_confidence': None,
        'final_pred': None,
        'final_confidence': None,
        'accessible': None,
        'timeout_occurred': False,
        'method_used': None,
        'error': None
    }
    
    try:
        # Enhanced prediction with timeout - is_single_analysis=False for batch
        enhanced_result = enhanced_url_prediction(url, use_ml, use_dl, timeout, is_single_analysis=False)
        
        result.update({
            'ml_pred': enhanced_result.get('ml_prediction'),
            'ml_confidence': enhanced_result.get('ml_confidence'),
            'dl_pred': enhanced_result.get('dl_prediction'),
            'dl_confidence': enhanced_result.get('dl_confidence'),
            'final_pred': enhanced_result.get('final_prediction'),
            'final_confidence': enhanced_result.get('final_confidence'),
            'accessible': enhanced_result.get('accessible'),
            'timeout_occurred': enhanced_result.get('timeout_occurred', False),
            'method_used': enhanced_result.get('method_used'),
            'error': enhanced_result.get('error')
        })
        
        # Regex analysis
        if use_regex:
            regex_analysis = analyze_url_with_regex(url)
            result['regex_pred'] = get_regex_prediction(url)
            result['regex_score'] = regex_analysis['total_score']
    
    except Exception as e:
        result['error'] = str(e)
    
    return result

# -----------------------------------------------------------------------------
# Sidebar Configuration
# -----------------------------------------------------------------------------
st.sidebar.header("Input Method")
input_method = st.sidebar.radio(
    "Choose input method:",
    ["Single URL Analysis", "Batch Prediction"]
)

st.sidebar.header("Analysis Options")
use_regex = st.sidebar.checkbox("Enable Regex Analysis", value=True)

# Different options for single vs batch
if input_method == "Single URL Analysis":
    st.sidebar.info("🔍 Single URL Logic:\n• Accessible URL → ML Model\n• Inaccessible URL → DL Model")
    use_ml_model = True  # Always enabled for single analysis
    use_dl_model = True  # Always enabled for single analysis
else:
    st.sidebar.info("📊 Batch Logic:\n• Uses both ML & DL models\n• Ensemble prediction")
    use_ml_model = st.sidebar.checkbox("Enable ML Model", value=True)
    use_dl_model = st.sidebar.checkbox("Enable DL Model", value=True)

st.sidebar.header("Timeout Settings")
timeout_seconds = st.sidebar.slider(
    "Timeout (seconds)", 
    min_value=5, 
    max_value=30, 
    value=10
)

st.sidebar.header("Performance Settings")
max_workers = st.sidebar.slider(
    "Parallel Workers", 
    min_value=1, 
    max_value=50, 
    value=10
)

# Status indicators
with st.sidebar:
    st.markdown("---")
    st.header("System Status")
    
    # Model availability
    st.markdown("**Models Loaded:**")
    if 'ml_model' in models:
        st.success("✅ ML Model (Fresh 30K Dataset)")
    else:
        st.error("❌ ML Model Not Loaded")
    
    if 'dl_model' in models:
        st.success("✅ DL Model")
    else:
        st.info("ℹ️ DL Model (Optional)")
    
    st.markdown("**Feature Extraction:**")
    if FEATURE_EXTRACTION_AVAILABLE:
        st.success("✅ Available")
    else:
        st.error("❌ Not Available")

# -----------------------------------------------------------------------------
# Single URL Analysis Section
# -----------------------------------------------------------------------------
if input_method == "Single URL Analysis":
    st.header("🔍 Single URL Analysis")
    st.info("**Smart Analysis Logic:** Accessible URLs use ML Model | Inaccessible URLs use DL Model")
    
    # Show model status clearly
    col1, col2 = st.columns(2)
    with col1:
        if 'ml_model' in models:
            st.success("✅ ML Model Ready (for accessible URLs)")
        else:
            st.error("❌ ML Model Not Loaded")
    
    with col2:
        if 'dl_model' in models:
            st.success("✅ DL Model Ready (for inaccessible URLs)")
        else:
            st.error("❌ DL Model Not Loaded")
    
    if 'ml_model' not in models and 'dl_model' not in models:
        st.error("❌ No models loaded. Cannot perform analysis.")
        st.stop()
    
    url_input = st.text_input("Enter URL:", placeholder="https://example.com")
    
    col1, col2 = st.columns(2)
    with col1:
        analyze_btn = st.button("🔍 Analyze URL", type="primary")
    with col2:
        quick_analyze_btn = st.button("⚡ Quick Analyze (5s timeout)")
    
    if analyze_btn or quick_analyze_btn:
        if not url_input.strip():
            st.error("Please enter a URL")
            st.stop()
        
        # Use quick timeout if quick analyze button pressed
        current_timeout = 5 if quick_analyze_btn else timeout_seconds
        
        # Add protocol if missing
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input
        
        # Enhanced analysis with is_single_analysis=True
        with st.spinner(f"Analyzing URL (timeout: {current_timeout}s)..."):
            result = enhanced_url_prediction(
                url_input, 
                use_ml=True, 
                use_dl=True, 
                timeout=current_timeout,
                is_single_analysis=True  # Enable single analysis mode
            )
        
        # Display results
        st.subheader("📊 Analysis Results")
        
        if result.get('error') and result.get('final_prediction') is None:
            st.error(f"❌ Analysis failed: {result['error']}")
        else:
            # Create result columns
            col1, col2, col3 = st.columns(3)
            
            with col1:
                final_pred = result.get('final_prediction', 0)
                final_conf = result.get('final_confidence', 0)
                if final_pred == 1:
                    st.metric("Final Prediction", "🛑 PHISHING", f"Confidence: {final_conf:.1%}")
                else:
                    st.metric("Final Prediction", "✅ LEGITIMATE", f"Confidence: {final_conf:.1%}")
            
            with col2:
                status = "✅ Accessible" if result.get('accessible') else "❌ Inaccessible"
                if result.get('timeout_occurred'):
                    status = "⏰ Timeout"
                st.metric("URL Status", status)
            
            with col3:
                method = result.get('method_used', 'Unknown').replace('_', ' ').title()
                
                # Show which model was used based on accessibility
                if result.get('accessible'):
                    model_icon = "🤖 ML Model"
                else:
                    model_icon = "🧠 DL Model"
                
                st.metric("Model Used", model_icon)
            
            # Explain why this model was chosen
            if result.get('accessible'):
                st.success("✅ URL is accessible → Using **ML Model** (trained on 30K fresh URLs)")
            else:
                st.info("🧠 URL is inaccessible → Using **DL Model** (character-level analysis)")
            
            # Detailed results
            with st.expander("🔍 Detailed Analysis"):
                if result.get('ml_prediction') is not None:
                    ml_pred = result.get('ml_prediction', 0)
                    ml_conf = result.get('ml_confidence', 0)
                    ml_label = '🛑 PHISHING' if ml_pred == 1 else '✅ LEGITIMATE'
                    st.write(f"**ML Model (Fresh 30K):** {ml_label} (confidence: {ml_conf:.1%})")
                
                if result.get('dl_prediction') is not None:
                    dl_pred = result.get('dl_prediction', 0)
                    dl_conf = result.get('dl_confidence', 0)
                    dl_label = '🛑 PHISHING' if dl_pred == 1 else '✅ LEGITIMATE'
                    st.write(f"**DL Model (Character-Level CNN):** {dl_label} (confidence: {dl_conf:.1%})")
                
                if use_regex:
                    regex_analysis = analyze_url_with_regex(url_input)
                    st.write(f"**Regex Analysis:** Score {regex_analysis['total_score']} ({regex_analysis['risk_level']} risk)")
                    
                    # Show detailed regex scores
                    if regex_analysis['total_score'] > 0:
                        st.write("**Regex Pattern Matches:**")
                        for pattern, score in regex_analysis['scores'].items():
                            if score > 0:
                                st.write(f"  - {pattern.replace('_', ' ').title()}: {score}")
                
                # Show timing information
                if result.get('accessibility_check_time'):
                    st.write(f"**Accessibility Check:** {result['accessibility_check_time']:.2f}s")
                
                # Show method details
                st.write(f"**Analysis Method:** {method}")
                
                # Show any errors
                if result.get('error'):
                    st.warning(f"⚠️ Note: {result['error']}")
            
            # Warning for low confidence
            final_confidence = result.get('final_confidence', 0)
            if final_confidence and final_confidence < 0.6:
                st.warning("⚠️ Low confidence prediction. Consider manual review.")
            elif final_confidence and final_confidence > 0.9:
                st.success("✅ High confidence prediction.")

# -----------------------------------------------------------------------------
# Batch Prediction Section
# -----------------------------------------------------------------------------
elif input_method == "Batch Prediction":
    st.header("📊 Batch URL Analysis")
    st.info("Process multiple URLs from a CSV file using Fresh ML Model")
    
    # Check model availability
    if 'ml_model' not in models:
        st.error("❌ ML Model is not loaded. Cannot perform batch analysis.")
        st.stop()
    
    uploaded_file = st.file_uploader("Upload CSV file with URLs", type=["csv"])

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        df.columns = df.columns.str.strip()

        st.write(f"**Data preview:** {len(df)} rows, {len(df.columns)} columns")
        st.dataframe(df.head())

        # Detect URL column
        url_columns = [c for c in df.columns if c.lower() in {"url", "website", "link"}]
        if not url_columns:
            st.error("❌ No URL column found. Please ensure your CSV has a column named 'URL', 'Website', or 'Link'")
            st.stop()
        
        url_column = url_columns[0]
        st.success(f"📌 Detected URL column: '{url_column}'")

        if st.button("🚀 Run Batch Analysis", type="primary"):
            try:
                st.info(f"🔄 Processing {len(df)} URLs with {timeout_seconds}s timeout...")
                
                # Prepare data for parallel processing
                url_data = [(idx, row[url_column], use_regex, use_ml_model, use_dl_model, timeout_seconds) 
                           for idx, row in df.iterrows()]
                
                # Process URLs in parallel with is_single_analysis=False for batch mode
                results = {}
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = [executor.submit(process_single_url_enhanced, data) for data in url_data]           for idx, row in df.iterrows()]
                
                # Process URLs in parallel
                results = {}
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = [executor.submit(process_single_url_enhanced, data) for data in url_data]
                    
                    for i, future in enumerate(as_completed(futures)):
                        result = future.result()
                        results[result['idx']] = result
                        
                        progress = (i + 1) / len(df)
                        progress_bar.progress(progress)
                        status_text.text(f"Completed: {i+1}/{len(df)} URLs")
                
                progress_bar.empty()
                status_text.empty()
                
                # Create results DataFrame
                results_df = df.copy()
                
                # Add all result columns
                for idx in range(len(df)):
                    if idx in results:
                        result = results[idx]
                        if use_regex:
                            results_df.at[idx, 'Regex_Prediction'] = result.get('regex_pred', 0)
                            results_df.at[idx, 'Regex_Score'] = result.get('regex_score', 0)
                        if use_ml_model:
                            results_df.at[idx, 'ML_Prediction'] = result.get('ml_pred', 0)
                            results_df.at[idx, 'ML_Confidence'] = result.get('ml_confidence', 0.5)
                        if use_dl_model:
                            results_df.at[idx, 'DL_Prediction'] = result.get('dl_pred', 0)
                            results_df.at[idx, 'DL_Confidence'] = result.get('dl_confidence', 0.5)
                        
                        results_df.at[idx, 'Final_Prediction'] = result.get('final_pred', 0)
                        results_df.at[idx, 'Final_Confidence'] = result.get('final_confidence', 0.5)
                        results_df.at[idx, 'URL_Accessible'] = result.get('accessible', False)
                        results_df.at[idx, 'Timeout_Occurred'] = result.get('timeout_occurred', False)
                        results_df.at[idx, 'Method_Used'] = result.get('method_used', 'unknown')
                
                st.success(f"✅ Batch analysis completed!")
                
                # Display summary statistics
                st.subheader("📊 Analysis Summary")
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total URLs", len(results_df))
                with col2:
                    timeouts = results_df['Timeout_Occurred'].sum()
                    st.metric("Timeouts", int(timeouts))
                with col3:
                    phishing_count = results_df['Final_Prediction'].sum()
                    st.metric("Phishing Detected", int(phishing_count))
                with col4:
                    avg_confidence = results_df['Final_Confidence'].mean()
                    st.metric("Avg Confidence", f"{avg_confidence:.1%}")
                
                # Method usage statistics
                if 'Method_Used' in results_df.columns:
                    st.subheader("🔧 Method Usage Distribution")
                    method_counts = results_df['Method_Used'].value_counts()
                    for method, count in method_counts.items():
                        st.write(f"- **{method.replace('_', ' ').title()}**: {count} URLs")
                
                # Download results
                st.subheader("📥 Download Results")
                csv_data = results_df.to_csv(index=False)
                
                st.download_button(
                    label="📥 Download Analysis Results (CSV)",
                    data=csv_data,
                    file_name="phishing_analysis_results.csv",
                    mime="text/csv",
                )
                
                # Display sample results
                st.subheader("🔍 Sample Results")
                display_cols = [url_column, 'Final_Prediction', 'Final_Confidence', 'Method_Used']
                if 'Timeout_Occurred' in results_df.columns:
                    display_cols.append('Timeout_Occurred')
                if 'URL_Accessible' in results_df.columns:
                    display_cols.append('URL_Accessible')
                
                # Create readable labels
                display_df = results_df[display_cols].copy()
                display_df['Final_Prediction'] = display_df['Final_Prediction'].map({0: 'Legitimate', 1: 'Phishing'})
                display_df['Final_Confidence'] = display_df['Final_Confidence'].apply(lambda x: f"{x:.1%}" if pd.notna(x) else "N/A")
                
                st.dataframe(display_df.head(20))
                
                # Show phishing URLs specifically
                phishing_urls = results_df[results_df['Final_Prediction'] == 1]
                if len(phishing_urls) > 0:
                    st.subheader("🚨 Detected Phishing URLs")
                    st.warning(f"Found {len(phishing_urls)} potentially malicious URLs")
                    
                    phishing_display = phishing_urls[[url_column, 'Final_Confidence', 'Method_Used']].copy()
                    phishing_display['Final_Confidence'] = phishing_display['Final_Confidence'].apply(lambda x: f"{x:.1%}" if pd.notna(x) else "N/A")
                    st.dataframe(phishing_display.head(10))

            except Exception as e:
                st.error(f"❌ Error in batch analysis: {e}")
                import traceback
                st.code(traceback.format_exc())

# -----------------------------------------------------------------------------
# Footer
# -----------------------------------------------------------------------------
st.markdown("---")
st.markdown("**Advanced Phishing Detection System | Fresh ML Model (30K Dataset)**")
st.caption("Powered by Stacking Ensemble ML model trained on 30,062 fresh, accessible URLs")# app.py — Updated for New Model Structure
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
st.markdown("**Detect malicious URLs using Fresh ML Model (30K URLs)**")

# -----------------------------------------------------------------------------
# Load Models - UPDATED FOR NEW STRUCTURE
# -----------------------------------------------------------------------------
APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent

# Updated model paths - looking in ML DL Trained Model directory
MODEL_DIR = ROOT_DIR / "ML DL Trained Model"

@st.cache_resource
def load_models():
    """Load ML model and scaler from ML DL Trained Model directory"""
    models = {}
    loaded_models = []
    
    st.sidebar.info("🔍 Loading models from ML DL Trained Model...")
    
    try:
        # Check if ML DL Trained Model directory exists
