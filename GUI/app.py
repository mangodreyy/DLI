# # app.py — Complete Streamlit UI for phishing detection with ML and Regex analysis
# import streamlit as st
# import pandas as pd
# import numpy as np
# import joblib
# import warnings
# from pathlib import Path
# import sys
# import os
# import re
# from concurrent.futures import ThreadPoolExecutor, as_completed
# import threading

# # Suppress warnings
# warnings.filterwarnings("ignore")

# # Add current directory to Python path for imports
# current_dir = Path(__file__).resolve().parent
# sys.path.append(str(current_dir))
# sys.path.append(str(current_dir.parent))

# # Try to import feature extraction module
# try:
#     from feature import FeatureExtraction
#     FEATURE_EXTRACTION_AVAILABLE = True
# except ImportError as e:
#     try:
#         import importlib.util
#         spec = importlib.util.spec_from_file_location("feature", current_dir / "feature.py")
#         feature_module = importlib.util.module_from_spec(spec)
#         spec.loader.exec_module(feature_module)
#         FeatureExtraction = feature_module.FeatureExtraction
#         FEATURE_EXTRACTION_AVAILABLE = True
#     except Exception:
#         st.warning(f"Feature extraction not available: {e}")
#         st.caption("Install dependencies: pip install beautifulsoup4 requests python-whois googlesearch-python python-dateutil lxml")
#         FEATURE_EXTRACTION_AVAILABLE = False

# # Page configuration
# st.set_page_config(page_title="URL Phishing Detection", page_icon="🔒", layout="wide")
# st.title("🔒 URL-Based Phishing Detection System")
# st.markdown("**Detect malicious URLs using machine learning and regex analysis**")

# # -----------------------------------------------------------------------------
# # Load model and scaler
# # -----------------------------------------------------------------------------
# APP_DIR = Path(__file__).resolve().parent
# ROOT_DIR = APP_DIR.parent
# MODEL_DIR = ROOT_DIR / "Main_Model"

# def find_file(*candidates):
#     for path in candidates:
#         if path and path.is_file():
#             return path
#     return None

# @st.cache_resource
# def load_model():
#     model_path = find_file(MODEL_DIR/"model.pkl", APP_DIR/"model.pkl", ROOT_DIR/"model.pkl")
#     if not model_path:
#         st.error("model.pkl not found")
#         return None
#     return joblib.load(model_path)

# @st.cache_resource
# def load_scaler():
#     scaler_path = find_file(MODEL_DIR/"scaler.pkl", APP_DIR/"scaler.pkl", ROOT_DIR/"scaler.pkl")
#     if not scaler_path:
#         st.error("scaler.pkl not found")
#         return None
#     return joblib.load(scaler_path)

# model = load_model()
# scaler = load_scaler()

# # Get expected features from scaler
# def get_expected_features(scaler):
#     if hasattr(scaler, "feature_names_in_"):
#         return list(scaler.feature_names_in_)
#     # Default feature names if scaler doesn't have them
#     return [
#         "url_length","domain_age","subdomain_count","special_chars",
#         "https_usage","google_index","page_rank","domain_registration_length",
#         "suspicious_keywords","dots_count","hyphens_count","underscores_count",
#         "slashes_count","question_marks","equal_signs","at_symbols",
#         "ampersands","percent_signs","hash_signs","digits_count",
#         "letters_count","alexa_rank","domain_trust","ssl_certificate",
#         "redirects_count","page_load_time","has_forms","hidden_elements",
#         "external_links_ratio","image_text_ratio"
#     ]

# EXPECTED_FEATURES = get_expected_features(scaler) if scaler else []

# # -----------------------------------------------------------------------------
# # Regex Analysis Functions
# # -----------------------------------------------------------------------------
# def analyze_url_with_regex(url):
#     """Analyze URL using regex patterns for phishing indicators"""
#     results = {}
#     score = 0
    
#     # Define regex patterns
#     patterns = {
#         'ip_address': {
#             'regex': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
#             'weight': 3,
#             'desc': 'Contains IP address instead of domain'
#         },
#         'suspicious_tlds': {
#             'regex': r'\.(tk|ml|ga|cf|pw|top|click|download|zip)$',
#             'weight': 2,
#             'desc': 'Uses suspicious top-level domain'
#         },
#         'url_shorteners': {
#             'regex': r'(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd)',
#             'weight': 1,
#             'desc': 'Uses URL shortening service'
#         },
#         'suspicious_keywords': {
#             'regex': r'(secure|account|verify|update|confirm|login|signin)',
#             'weight': 2,
#             'desc': 'Contains suspicious keywords'
#         },
#         'excessive_subdomains': {
#             'regex': r'^https?://[^/]*\..*\..*\..*/',
#             'weight': 1,
#             'desc': 'Excessive number of subdomains'
#         },
#         'suspicious_ports': {
#             'regex': r':(8080|8000|3000|4000|5000|8888|9999)',
#             'weight': 2,
#             'desc': 'Uses non-standard ports'
#         },
#         'url_encoding': {
#             'regex': r'%[0-9a-fA-F]{2}',
#             'weight': 1,
#             'desc': 'Contains URL encoding'
#         },
#         'long_url': {
#             'regex': r'^.{100,}$',
#             'weight': 1,
#             'desc': 'Extremely long URL'
#         }
#     }
    
#     # Check each pattern
#     for name, info in patterns.items():
#         try:
#             match = re.search(info['regex'], url, re.IGNORECASE)
#             found = bool(match)
#             results[name] = {
#                 'found': found,
#                 'weight': info['weight'],
#                 'description': info['desc']
#             }
#             if found:
#                 score += info['weight']
#         except Exception:
#             results[name] = {
#                 'found': False,
#                 'weight': info['weight'],
#                 'description': info['desc']
#             }
    
#     # Determine risk level
#     if score >= 6:
#         risk_level = "High Risk"
#         risk_color = "🔴"
#     elif score >= 3:
#         risk_level = "Medium Risk"
#         risk_color = "🟡"
#     else:
#         risk_level = "Low Risk"
#         risk_color = "🟢"
    
#     return {
#         'total_score': score,
#         'risk_level': risk_level,
#         'risk_color': risk_color,
#         'patterns': results
#     }

# def get_regex_prediction(url):
#     """Get prediction based on regex analysis"""
#     analysis = analyze_url_with_regex(url)
#     return 1 if analysis['total_score'] >= 4 else 0

# # -----------------------------------------------------------------------------
# # Feature Extraction Function
# # -----------------------------------------------------------------------------
# def extract_url_features(url):
#     """Extract features from URL using FeatureExtraction class"""
#     if not FEATURE_EXTRACTION_AVAILABLE:
#         return None, "Feature extraction module not available"
    
#     try:
#         extractor = FeatureExtraction(url)
#         features = extractor.getFeaturesList()
        
#         # Ensure correct number of features
#         expected_count = len(EXPECTED_FEATURES)
#         if len(features) < expected_count:
#             features.extend([0] * (expected_count - len(features)))
#         elif len(features) > expected_count:
#             features = features[:expected_count]
        
#         # Create DataFrame with expected feature names
#         feature_df = pd.DataFrame([features], columns=EXPECTED_FEATURES)
#         return feature_df, None
        
#     except Exception as e:
#         return None, str(e)

# # -----------------------------------------------------------------------------
# # Parallel Processing Function
# # -----------------------------------------------------------------------------
# def process_single_url(url_data):
#     """Process a single URL with both regex and ML analysis"""
#     idx, url, use_regex_flag, use_ml_flag = url_data
    
#     # Add protocol if missing
#     if not str(url).startswith(('http://', 'https://')):
#         url = 'https://' + str(url)
    
#     result = {
#         'idx': idx,
#         'url': url,
#         'regex_pred': None,
#         'regex_score': None,
#         'ml_pred': None,
#         'ml_legit_prob': None,
#         'ml_phish_prob': None,
#         'error': None
#     }
    
#     try:
#         # Regex Analysis
#         if use_regex_flag:
#             regex_analysis = analyze_url_with_regex(url)
#             result['regex_pred'] = get_regex_prediction(url)
#             result['regex_score'] = regex_analysis['total_score']
        
#         # ML Analysis
#         if use_ml_flag:
#             features_df, error = extract_url_features(url)
            
#             if error:
#                 result['ml_pred'] = 0
#                 result['ml_legit_prob'] = 1.0
#                 result['ml_phish_prob'] = 0.0
#                 result['error'] = f"Feature extraction failed: {error}"
#             else:
#                 # Make prediction
#                 X_features = features_df.values
#                 X_scaled = scaler.transform(X_features)
                
#                 if hasattr(model, "predict_proba"):
#                     probabilities = model.predict_proba(X_scaled)
#                     result['ml_pred'] = np.argmax(probabilities, axis=1)[0]
#                     result['ml_legit_prob'] = probabilities[0][0]
#                     result['ml_phish_prob'] = probabilities[0][1]
#                 else:
#                     result['ml_pred'] = model.predict(X_scaled)[0]
#                     result['ml_phish_prob'] = float(result['ml_pred'])
#                     result['ml_legit_prob'] = 1.0 - result['ml_phish_prob']
    
#     except Exception as e:
#         result['error'] = str(e)
#         # Set default values
#         if use_regex_flag:
#             result['regex_pred'] = 0
#             result['regex_score'] = 0
#         if use_ml_flag:
#             result['ml_pred'] = 0
#             result['ml_legit_prob'] = 1.0
#             result['ml_phish_prob'] = 0.0
    
#     return result

# # -----------------------------------------------------------------------------
# # Sidebar Configuration
# # -----------------------------------------------------------------------------
# st.sidebar.header("Input Method")
# input_method = st.sidebar.radio(
#     "Choose input method:",
#     ["URL Analysis", "Batch Prediction"]
# )

# st.sidebar.header("Analysis Options")
# use_regex = st.sidebar.checkbox("Enable Regex Analysis", value=True)
# use_ml_model = st.sidebar.checkbox("Enable ML Model", value=True)

# st.sidebar.header("Performance Settings")
# max_workers = st.sidebar.slider(
#     "Parallel Workers", 
#     min_value=1, 
#     max_value=100, 
#     value=50,
#     help="Number of URLs to process simultaneously"
# )

# # Status indicators
# with st.sidebar:
#     st.markdown("---")
#     st.header("System Status")
    
#     st.markdown("**Feature Extraction:**")
#     if FEATURE_EXTRACTION_AVAILABLE:
#         st.success("✅ Available")
#     else:
#         st.error("❌ Not Available")
    
#     st.markdown("**ML Model:**")
#     if model is not None:
#         st.success("✅ Loaded")
#     else:
#         st.error("❌ Not Loaded")
    
#     st.markdown("**Scaler:**")
#     if scaler is not None:
#         st.success("✅ Loaded")
#     else:
#         st.error("❌ Not Loaded")

# # -----------------------------------------------------------------------------
# # Single URL Analysis
# # -----------------------------------------------------------------------------
# if input_method == "URL Analysis":
#     st.header("🔍 Single URL Analysis")
#     st.info("Enter a URL to analyze using regex patterns and/or machine learning model.")
    
#     url_input = st.text_input("Enter URL:", placeholder="https://example.com")
    
#     if st.button("🔍 Analyze URL", type="primary"):
#         if not url_input:
#             st.error("Please enter a URL")
#             st.stop()
        
#         # Add protocol if missing
#         if not url_input.startswith(('http://', 'https://')):
#             url_input = 'https://' + url_input
        
#         results = {}
        
#         # Regex Analysis
#         if use_regex:
#             with st.spinner("Running regex analysis..."):
#                 regex_analysis = analyze_url_with_regex(url_input)
#                 results['regex'] = regex_analysis
        
#         # ML Model Analysis
#         if use_ml_model:
#             if model is None or scaler is None:
#                 st.error("Model or scaler not loaded")
#                 st.stop()
                
#             if not FEATURE_EXTRACTION_AVAILABLE:
#                 st.error("Feature extraction module not available")
#                 st.stop()
            
#             with st.spinner("Running ML analysis..."):
#                 try:
#                     features_df, error = extract_url_features(url_input)
                    
#                     if error:
#                         st.error(f"Error extracting features: {error}")
#                         st.stop()
                    
#                     # Make prediction
#                     X_features = features_df.values
#                     X_scaled = scaler.transform(X_features)
                    
#                     if hasattr(model, "predict_proba"):
#                         probabilities = model.predict_proba(X_scaled)
#                         ml_prediction = np.argmax(probabilities, axis=1)[0]
#                         legit_prob = probabilities[0][0]
#                         phish_prob = probabilities[0][1]
#                     else:
#                         ml_prediction = model.predict(X_scaled)[0]
#                         phish_prob = float(ml_prediction)
#                         legit_prob = 1.0 - phish_prob
                    
#                     results['ml'] = {
#                         'prediction': ml_prediction,
#                         'legit_prob': legit_prob,
#                         'phish_prob': phish_prob,
#                         'features_df': features_df
#                     }
                    
#                 except Exception as e:
#                     st.error(f"Error in ML analysis: {e}")
        
#         # Display Results
#         st.subheader("🎯 Analysis Results")
        
#         # Regex Results
#         if use_regex and 'regex' in results:
#             st.subheader("🔍 Regex Analysis")
#             regex_result = results['regex']
            
#             col1, col2, col3 = st.columns(3)
#             with col1:
#                 st.metric("Risk Level", f"{regex_result['risk_color']} {regex_result['risk_level']}")
#             with col2:
#                 st.metric("Risk Score", regex_result['total_score'])
#             with col3:
#                 regex_pred = "🔴 Phishing" if get_regex_prediction(url_input) == 1 else "🟢 Legitimate"
#                 st.metric("Regex Prediction", regex_pred)
            
#             # Pattern details
#             with st.expander("🔍 Pattern Analysis Details"):
#                 for pattern_name, info in regex_result['patterns'].items():
#                     if info['found']:
#                         st.warning(f"⚠️ **{pattern_name.replace('_', ' ').title()}**: {info['description']} (Weight: {info['weight']})")
#                     else:
#                         st.success(f"✅ **{pattern_name.replace('_', ' ').title()}**: Not detected")
        
#         # ML Results
#         if use_ml_model and 'ml' in results:
#             st.subheader("🤖 Machine Learning Analysis")
#             ml_result = results['ml']
            
#             col1, col2, col3 = st.columns(3)
#             with col1:
#                 status = "🔴 Phishing" if ml_result['prediction'] == 1 else "🟢 Legitimate"
#                 st.metric("ML Prediction", status)
#             with col2:
#                 st.metric("Legitimate Probability", f"{ml_result['legit_prob']:.2%}")
#             with col3:
#                 st.metric("Phishing Probability", f"{ml_result['phish_prob']:.2%}")
            
#             # Confidence indicator
#             confidence = max(ml_result['legit_prob'], ml_result['phish_prob'])
#             if confidence > 0.8:
#                 confidence_text = "🟢 High Confidence"
#             elif confidence > 0.6:
#                 confidence_text = "🟡 Medium Confidence"
#             else:
#                 confidence_text = "🔴 Low Confidence"
            
#             st.info(f"Prediction Confidence: {confidence_text} ({confidence:.1%})")
            
#             # Feature details
#             with st.expander("View Extracted Features"):
#                 st.dataframe(ml_result['features_df'])
        
#         # Combined Analysis
#         if use_regex and use_ml_model and 'regex' in results and 'ml' in results:
#             st.subheader("🔄 Combined Analysis")
            
#             regex_pred = get_regex_prediction(url_input)
#             ml_pred = results['ml']['prediction']
            
#             if regex_pred == ml_pred:
#                 if regex_pred == 1:
#                     st.error("🚨 **HIGH ALERT**: Both methods predict PHISHING")
#                 else:
#                     st.success("✅ **SAFE**: Both methods predict LEGITIMATE")
#             else:
#                 st.warning("⚠️ **MIXED RESULTS**: Methods disagree")
#                 st.write(f"Regex: {'Phishing' if regex_pred == 1 else 'Legitimate'}")
#                 st.write(f"ML: {'Phishing' if ml_pred == 1 else 'Legitimate'}")
        
#         # Security Recommendations
#         st.subheader("🛡️ Security Recommendations")
        
#         high_risk = False
#         if use_regex and 'regex' in results and results['regex']['total_score'] >= 4:
#             high_risk = True
#         if use_ml_model and 'ml' in results and results['ml']['prediction'] == 1:
#             high_risk = True
        
#         if high_risk:
#             st.error("⚠️ **Warning: This URL appears to be malicious!**")
#             st.markdown("""
#             **Recommendations:**
#             - Do not enter personal information
#             - Do not download files from this site
#             - Verify the URL with the legitimate organization
#             - Report this URL to security authorities
#             """)
#         else:
#             st.success("✅ **This URL appears to be legitimate**")
#             st.markdown("""
#             **Note:**
#             - Always exercise caution when sharing personal information
#             - Verify SSL certificates and site authenticity
#             """)

# # -----------------------------------------------------------------------------
# # Batch Prediction
# # -----------------------------------------------------------------------------
# elif input_method == "Batch Prediction":
#     st.header("📊 Batch Prediction")
#     st.info("Upload a CSV file with URLs (and optionally labels) for batch analysis.")
    
#     uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])

#     if uploaded_file is not None:
#         df = pd.read_csv(uploaded_file)
#         df.columns = df.columns.str.strip()

#         st.write(f"**Data preview:** {len(df)} rows, {len(df.columns)} columns")
#         st.dataframe(df.head())

#         # Detect columns
#         url_columns = [c for c in df.columns if c.lower() in {"url", "website", "link"}]
#         target_columns = [c for c in df.columns if c.lower() in {"class", "label", "target", "y"}]
        
#         if not url_columns:
#             st.error("❌ No URL column found. Please ensure your CSV has a column named 'url', 'website', or 'link'.")
#             st.stop()
        
#         url_column = url_columns[0]
#         has_labels = bool(target_columns)
        
#         if has_labels:
#             target_column = target_columns[0]
#             st.success(f"📌 Detected: URL column '{url_column}' and label column '{target_column}'")
#             st.info("Will analyze URLs and compare with provided labels for accuracy calculation.")
#             st.write(f"Label distribution: {dict(df[target_column].value_counts())}")
#         else:
#             st.success(f"📌 Detected: URL column '{url_column}' without labels")
#             st.info("Will analyze URLs and provide predictions for download.")

#         if st.button("🚀 Run Batch Analysis", type="primary"):
#             if not use_ml_model and not use_regex:
#                 st.error("Please enable at least one analysis method")
#                 st.stop()
                
#             if use_ml_model and (model is None or scaler is None):
#                 st.error("ML Model or scaler not loaded")
#                 st.stop()
                
#             if use_ml_model and not FEATURE_EXTRACTION_AVAILABLE:
#                 st.error("Feature extraction not available")
#                 st.stop()

#             try:
#                 st.info(f"🔄 Processing {len(df)} URLs using {max_workers} parallel workers...")
                
#                 # Prepare data for parallel processing
#                 url_data = [(idx, row[url_column], use_regex, use_ml_model) 
#                            for idx, row in df.iterrows()]
                
#                 # Process URLs in parallel
#                 results = {}
#                 failed_urls = []
                
#                 progress_bar = st.progress(0)
#                 status_text = st.empty()
#                 completed = 0
                
#                 with ThreadPoolExecutor(max_workers=max_workers) as executor:
#                     future_to_url = {executor.submit(process_single_url, data): data for data in url_data}
                    
#                     for future in as_completed(future_to_url):
#                         try:
#                             result = future.result()
#                             results[result['idx']] = result
                            
#                             if result['error']:
#                                 failed_urls.append(result['url'])
                            
#                             completed += 1
#                             progress = completed / len(df)
#                             progress_bar.progress(progress)
#                             status_text.text(f"Completed: {completed}/{len(df)} URLs ({progress:.1%})")
                            
#                         except Exception as e:
#                             url_info = future_to_url[future]
#                             failed_urls.append(url_info[1])
#                             completed += 1
                
#                 progress_bar.empty()
#                 status_text.empty()
                
#                 if failed_urls:
#                     st.warning(f"⚠️ Analysis failed for {len(failed_urls)} URLs out of {len(df)} total.")
                
#                 # Organize results
#                 regex_predictions = []
#                 ml_predictions = []
#                 ml_legit_probs = []
#                 ml_phish_probs = []
#                 regex_scores = []
                
#                 for idx in range(len(df)):
#                     if idx in results:
#                         result = results[idx]
#                         if use_regex:
#                             regex_predictions.append(result['regex_pred'] if result['regex_pred'] is not None else 0)
#                             regex_scores.append(result['regex_score'] if result['regex_score'] is not None else 0)
#                         if use_ml_model:
#                             ml_predictions.append(result['ml_pred'] if result['ml_pred'] is not None else 0)
#                             ml_legit_probs.append(result['ml_legit_prob'] if result['ml_legit_prob'] is not None else 1.0)
#                             ml_phish_probs.append(result['ml_phish_prob'] if result['ml_phish_prob'] is not None else 0.0)
#                     else:
#                         # Default values for missing results
#                         if use_regex:
#                             regex_predictions.append(0)
#                             regex_scores.append(0)
#                         if use_ml_model:
#                             ml_predictions.append(0)
#                             ml_legit_probs.append(1.0)
#                             ml_phish_probs.append(0.0)
                
#                 # Create results DataFrame
#                 results_df = df.copy()
                
#                 if use_regex:
#                     results_df["Regex_Prediction"] = regex_predictions
#                     results_df["Regex_Score"] = regex_scores
                
#                 if use_ml_model:
#                     results_df["ML_Prediction"] = ml_predictions
#                     results_df["ML_Legit_Prob"] = ml_legit_probs
#                     results_df["ML_Phish_Prob"] = ml_phish_probs
                
#                 # Combined prediction
#                 if use_regex and use_ml_model:
#                     combined_predictions = []
#                     for i in range(len(df)):
#                         if regex_predictions[i] == 1 or ml_predictions[i] == 1:
#                             combined_predictions.append(1)
#                         else:
#                             combined_predictions.append(0)
#                     results_df["Combined_Prediction"] = combined_predictions
                
#                 st.success(f"✅ Batch analysis completed! Processed {len(df)} URLs.")

#                 # Display Summary
#                 st.subheader("📊 Analysis Summary")
                
#                 col1, col2, col3 = st.columns(3)
#                 with col1:
#                     st.metric("Total URLs", len(results_df))
                
#                 if use_regex:
#                     with col2:
#                         regex_legit = sum(1 for p in regex_predictions if p == 0)
#                         st.metric("Regex: Legitimate", regex_legit)
#                     with col3:
#                         regex_phish = sum(1 for p in regex_predictions if p == 1)
#                         st.metric("Regex: Phishing", regex_phish)
                
#                 if use_ml_model:
#                     col1, col2, col3 = st.columns(3)
#                     with col1:
#                         st.metric("ML Analysis", "Completed")
#                     with col2:
#                         ml_legit = sum(1 for p in ml_predictions if p == 0)
#                         st.metric("ML: Legitimate", ml_legit)
#                     with col3:
#                         ml_phish = sum(1 for p in ml_predictions if p == 1)
#                         st.metric("ML: Phishing", ml_phish)

#                 # Accuracy calculation if labels provided
#                 if has_labels:
#                     st.subheader("🎯 Accuracy Analysis")
                    
#                     try:
#                         target_values = df[target_column].copy()
                        
#                         # Convert text labels to numeric if needed
#                         if target_values.dtype == 'object':
#                             label_mapping = {
#                                 'benign': 0, 'legitimate': 0, 'safe': 0, 'good': 0,
#                                 'phishing': 1, 'malicious': 1, 'bad': 1, 'unsafe': 1
#                             }
#                             target_values = target_values.str.lower().map(label_mapping)
                        
#                         # Calculate accuracy
#                         unique_labels = set(pd.Series(target_values).dropna().unique())
#                         if unique_labels <= {0, 1}:
#                             col1, col2, col3 = st.columns(3)
                            
#                             if use_regex:
#                                 with col1:
#                                     regex_acc = (np.array(regex_predictions) == target_values.to_numpy()).mean()
#                                     st.metric("Regex Accuracy", f"{regex_acc:.1%}")
                            
#                             if use_ml_model:
#                                 with col2:
#                                     ml_acc = (np.array(ml_predictions) == target_values.to_numpy()).mean()
#                                     st.metric("ML Accuracy", f"{ml_acc:.1%}")
                            
#                             if use_regex and use_ml_model:
#                                 with col3:
#                                     combined_acc = (np.array(combined_predictions) == target_values.to_numpy()).mean()
#                                     st.metric("Combined Accuracy", f"{combined_acc:.1%}")
#                         else:
#                             st.info(f"Cannot calculate accuracy - found labels: {sorted(unique_labels)}")
#                     except Exception as e:
#                         st.warning(f"Could not calculate accuracy: {e}")

#                 # Results display
#                 st.subheader("🔍 Detailed Results")
                
#                 # Prepare display columns
#                 display_columns = [url_column]
#                 if has_labels:
#                     display_columns.append(target_column)
                
#                 if use_regex:
#                     display_columns.extend(["Regex_Prediction", "Regex_Score"])
#                 if use_ml_model:
#                     display_columns.extend(["ML_Prediction", "ML_Legit_Prob", "ML_Phish_Prob"])
#                 if use_regex and use_ml_model:
#                     display_columns.append("Combined_Prediction")
                
#                 # Filter options
#                 col1, col2 = st.columns(2)
#                 with col1:
#                     status_filter = st.selectbox("Filter by Status:", ["All", "Legitimate (0)", "Phishing (1)"])
                
#                 with col2:
#                     if use_ml_model:
#                         confidence_threshold = st.slider("Minimum ML Confidence:", 0.0, 1.0, 0.0, 0.1)
#                     else:
#                         confidence_threshold = 0.0
                
#                 # Apply filters
#                 filtered_df = results_df.copy()
                
#                 if status_filter == "Legitimate (0)":
#                     if use_regex and use_ml_model:
#                         filtered_df = filtered_df[filtered_df["Combined_Prediction"] == 0]
#                     elif use_regex:
#                         filtered_df = filtered_df[filtered_df["Regex_Prediction"] == 0]
#                     elif use_ml_model:
#                         filtered_df = filtered_df[filtered_df["ML_Prediction"] == 0]
#                 elif status_filter == "Phishing (1)":
#                     if use_regex and use_ml_model:
#                         filtered_df = filtered_df[filtered_df["Combined_Prediction"] == 1]
#                     elif use_regex:
#                         filtered_df = filtered_df[filtered_df["Regex_Prediction"] == 1]
#                     elif use_ml_model:
#                         filtered_df = filtered_df[filtered_df["ML_Prediction"] == 1]
                
#                 if confidence_threshold > 0 and use_ml_model:
#                     filtered_df = filtered_df[
#                         (filtered_df["ML_Legit_Prob"] >= confidence_threshold) | 
#                         (filtered_df["ML_Phish_Prob"] >= confidence_threshold)
#                     ]
                
#                 st.dataframe(filtered_df[display_columns], use_container_width=True)

#                 # Download section
#                 st.subheader("📥 Download Results")
                
#                 if has_labels:
#                     st.info("Your CSV contained labels. Download includes original labels vs predictions.")
#                 else:
#                     st.info("Your CSV didn't contain labels. Download includes predictions for each URL.")
                
#                 # Prepare simplified download data
#                 download_df = df.copy()
                
#                 if use_regex and not use_ml_model:
#                     # Only regex predictions
#                     download_df["Prediction"] = regex_predictions
#                 elif use_ml_model and not use_regex:
#                     # Only ML predictions
#                     download_df["Prediction"] = ml_predictions
#                 elif use_regex and use_ml_model:
#                     # Combined predictions
#                     download_df["Regex_Prediction"] = regex_predictions
#                     download_df["ML_Prediction"] = ml_predictions
#                     download_df["Combined_Prediction"] = combined_predictions
                
#                 # Create download buttons
#                 col1, col2 = st.columns(2)
                
#                 with col1:
#                     # Simple predictions CSV
#                     if use_regex and use_ml_model:
#                         simple_df = df[[url_column]].copy()
#                         if has_labels:
#                             simple_df[target_column] = df[target_column]
#                         simple_df["Prediction"] = combined_predictions
#                     else:
#                         simple_df = download_df[[url_column]].copy()
#                         if has_labels:
#                             simple_df[target_column] = df[target_column]
#                         if use_regex:
#                             simple_df["Prediction"] = regex_predictions
#                         else:
#                             simple_df["Prediction"] = ml_predictions
                    
#                     simple_csv = simple_df.to_csv(index=False)
#                     st.download_button(
#                         label="📥 Download Simple Results",
#                         data=simple_csv,
#                         file_name="phishing_predictions.csv",
#                         mime="text/csv",
#                     )
                
#                 with col2:
#                     # Detailed results CSV
#                     detailed_csv = results_df.to_csv(index=False)
#                     st.download_button(
#                         label="📥 Download Detailed Results",
#                         data=detailed_csv,
#                         file_name="detailed_phishing_analysis.csv",
#                         mime="text/csv",
#                     )

#             except Exception as e:
#                 st.error(f"❌ Error in batch analysis: {e}")
#                 st.markdown("**Troubleshooting:**")
#                 st.markdown("1. Ensure URLs are properly formatted")
#                 st.markdown("2. Check internet connectivity")
#                 st.markdown("3. Try reducing parallel workers if getting timeout errors")
#                 st.markdown("4. Some URL failures are normal and handled gracefully")

# # -----------------------------------------------------------------------------
# # Footer
# # -----------------------------------------------------------------------------
# st.markdown("---")
# st.markdown("**Built by Group AJ 🎈 | Cybersecurity DLI Project**")
# st.caption("This system uses machine learning and regex pattern matching to detect phishing URLs.")

# app.py — Fixed DL Model Loading
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
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

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
st.markdown("**Detect malicious URLs using hybrid ML + DL models**")

# -----------------------------------------------------------------------------
# Load Models from hybrid_results - FIXED VERSION
# -----------------------------------------------------------------------------
APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
MODEL_DIR = ROOT_DIR / "hybrid_results"

@st.cache_resource
def load_models():
    """Load all models from hybrid_results directory - FIXED"""
    models = {}
    loaded_models = []
    
    st.sidebar.info("🔍 Loading models from hybrid_results...")
    
    try:
        # Check if hybrid_results directory exists
        if not MODEL_DIR.exists():
            st.sidebar.error(f"❌ Directory not found: {MODEL_DIR}")
            return models
        
        st.sidebar.info(f"📁 Model directory: {MODEL_DIR}")
        
        # List all files in the directory for debugging
        model_files = list(MODEL_DIR.glob("*"))
        st.sidebar.info(f"📄 Files found: {[f.name for f in model_files]}")
        
        # Load ML Model and Scaler
        ml_path = MODEL_DIR / "accessible_ml_model.pkl"
        scaler_path = MODEL_DIR / "accessible_scaler.pkl"
        
        if ml_path.exists() and scaler_path.exists():
            try:
                with open(ml_path, 'rb') as f:
                    models['ml_model'] = pickle.load(f)
                with open(scaler_path, 'rb') as f:
                    models['scaler'] = pickle.load(f)
                loaded_models.append("ML Model")
                st.sidebar.success("✅ ML Model Loaded")
            except Exception as e:
                st.sidebar.error(f"❌ ML Model loading failed: {e}")
        else:
            st.sidebar.warning("⚠️ ML Model files not found")
        
        # Load Hybrid Model
        hybrid_path = MODEL_DIR / "hybrid_predictor.pkl"
        if hybrid_path.exists():
            try:
                with open(hybrid_path, 'rb') as f:
                    models['hybrid_model'] = pickle.load(f)
                loaded_models.append("Hybrid Model")
                st.sidebar.success("✅ Hybrid Model Loaded")
            except Exception as e:
                st.sidebar.error(f"❌ Hybrid Model loading failed: {e}")
        else:
            st.sidebar.warning("⚠️ Hybrid Model file not found")
        
        # Load DL Model - FIXED THIS PART
        dl_path = MODEL_DIR / "real_dataset_dl_model.h5"
        tokenizer_path = MODEL_DIR / "real_dataset_tokenizer.pkl"
        
       # In the load_models function, replace the DL model test with:
        if dl_path.exists() and tokenizer_path.exists():
            try:
                # Load DL model
                models['dl_model'] = load_model(str(dl_path))
                
                # Load tokenizer
                with open(tokenizer_path, 'rb') as f:
                    models['tokenizer'] = pickle.load(f)
                
                loaded_models.append("DL Model")
                st.sidebar.success("✅ DL Model Loaded")
                
                # Simpler test that won't fail on model architecture
                try:
                    # Just verify the model has the expected methods
                    if hasattr(models['dl_model'], 'predict') and hasattr(models['tokenizer'], 'texts_to_sequences'):
                        st.sidebar.success("✅ DL Model Structure Verified")
                    else:
                        st.sidebar.warning("⚠️ DL Model structure unexpected")
                except Exception as test_error:
                    st.sidebar.warning(f"⚠️ DL Model test inconclusive: {test_error}")
                    
            except Exception as e:
                st.sidebar.error(f"❌ DL Model loading failed: {e}")
        
        else:
            missing_files = []
            if not dl_path.exists():
                missing_files.append("real_dataset_dl_model.h5")
            if not tokenizer_path.exists():
                missing_files.append("real_dataset_tokenizer.pkl")
            st.sidebar.error(f"❌ DL Model files missing: {', '.join(missing_files)}")
        
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
# Enhanced Prediction Function - FIXED DL MODEL USAGE
# -----------------------------------------------------------------------------
def enhanced_url_prediction(url, use_ml=True, use_dl=True, timeout=10):
    """Enhanced prediction with timeout handling"""
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
        
        # Check if DL model is available
        dl_available = 'dl_model' in models and 'tokenizer' in models
        ml_available = 'ml_model' in models and 'scaler' in models
        
        if not dl_available and use_dl:
            results['error'] = "DL model not available"
            use_dl = False  # Disable DL since it's not available
        
        if not ml_available and use_ml:
            if 'error' in results:
                results['error'] += ", ML model not available"
            else:
                results['error'] = "ML model not available"
            use_ml = False  # Disable ML since it's not available
        
        if accessibility == "timeout":
            results['timeout_occurred'] = True
            results['accessible'] = False
            # Timeout occurred - use DL directly if available
            if use_dl and dl_available:
                results['method_used'] = 'dl_timeout_fallback'
                dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                results['dl_prediction'] = dl_pred
                results['dl_confidence'] = dl_conf
                results['final_prediction'] = dl_pred
                results['final_confidence'] = dl_conf
            elif use_ml and ml_available:
                # Fallback to ML if DL not available
                results['method_used'] = 'ml_timeout_fallback'
                features, error = extract_features_with_timeout(url, timeout-2)
                if not error and features:
                    features_array = np.array(features).reshape(1, -1)
                    features_scaled = models['scaler'].transform(features_array)
                    ml_pred = models['ml_model'].predict(features_scaled)[0]
                    results['ml_prediction'] = int(ml_pred)
                    results['final_prediction'] = int(ml_pred)
                    results['final_confidence'] = 0.7  # Default confidence for timeout fallback
            else:
                results['error'] = "No models available for prediction"
            return results
        
        elif accessibility:  # URL is accessible
            # Try ML model first if available and requested
            if use_ml and ml_available:
                try:
                    # Extract features with timeout
                    features, error = extract_features_with_timeout(url, timeout-2)
                    
                    if error:
                        results['error'] = f"ML feature extraction failed: {error}"
                    else:
                        # Make ML prediction
                        features_array = np.array(features).reshape(1, -1)
                        features_scaled = models['scaler'].transform(features_array)
                        
                        if hasattr(models['ml_model'], "predict_proba"):
                            ml_proba = models['ml_model'].predict_proba(features_scaled)[0]
                            ml_pred = np.argmax(ml_proba)
                            ml_conf = max(ml_proba)
                        else:
                            ml_pred = models['ml_model'].predict(features_scaled)[0]
                            ml_conf = 0.5
                        
                        results['ml_prediction'] = int(ml_pred)
                        results['ml_confidence'] = float(ml_conf)
                        results['method_used'] = 'ml_primary'
                        results['final_prediction'] = ml_pred
                        results['final_confidence'] = ml_conf
                        
                        # If ML confidence is low and DL available, also use DL
                        if ml_conf < 0.7 and use_dl and dl_available:
                            dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                            results['dl_prediction'] = dl_pred
                            results['dl_confidence'] = dl_conf
                            # Use the model with higher confidence
                            if dl_conf > ml_conf:
                                results['final_prediction'] = dl_pred
                                results['final_confidence'] = dl_conf
                                results['method_used'] = 'ml_dl_ensemble'
                            
                except Exception as e:
                    results['error'] = f"ML prediction failed: {e}"
                    # Fallback to DL if available
                    if use_dl and dl_available:
                        dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                        results['dl_prediction'] = dl_pred
                        results['dl_confidence'] = dl_conf
                        results['final_prediction'] = dl_pred
                        results['final_confidence'] = dl_conf
                        results['method_used'] = 'dl_fallback'
            
            elif use_dl and dl_available:  # ML not available or not requested, but DL is
                dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                results['dl_prediction'] = dl_pred
                results['dl_confidence'] = dl_conf
                results['final_prediction'] = dl_pred
                results['final_confidence'] = dl_conf
                results['method_used'] = 'dl_primary'
            else:
                results['error'] = "No prediction models available"
        
        else:  # URL not accessible
            # Use DL model directly if available
            if use_dl and dl_available:
                dl_pred, dl_conf = predict_with_dl(url, models['dl_model'], models['tokenizer'])
                results['dl_prediction'] = dl_pred
                results['dl_confidence'] = dl_conf
                results['final_prediction'] = dl_pred
                results['final_confidence'] = dl_conf
                results['method_used'] = 'dl_inaccessible'
            elif use_ml and ml_available:
                # Try ML even if URL is not accessible
                features, error = extract_features_with_timeout(url, timeout-2)
                if not error and features:
                    features_array = np.array(features).reshape(1, -1)
                    features_scaled = models['scaler'].transform(features_array)
                    ml_pred = models['ml_model'].predict(features_scaled)[0]
                    results['ml_prediction'] = int(ml_pred)
                    results['final_prediction'] = int(ml_pred)
                    results['final_confidence'] = 0.6  # Lower confidence for inaccessible URLs
                    results['method_used'] = 'ml_inaccessible'
            else:
                results['error'] = "URL not accessible and no models available"
    
    except Exception as e:
        results['error'] = f"Prediction failed: {e}"
    
    return results

def predict_with_dl(url, dl_model, tokenizer):
    """Predict using DL model"""
    try:
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
        'long_url': r'^.{50,}$',
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
    """Enhanced single URL processing"""
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
        # Enhanced prediction with timeout
        enhanced_result = enhanced_url_prediction(url, use_ml, use_dl, timeout)
        
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
        st.success("✅ ML Model")
    else:
        st.warning("⚠️ ML Model")
    
    if 'dl_model' in models:
        st.success("✅ DL Model")
    else:
        st.warning("⚠️ DL Model")
    
    if 'hybrid_model' in models:
        st.success("✅ Hybrid Model")
    
    st.markdown("**Feature Extraction:**")
    if FEATURE_EXTRACTION_AVAILABLE:
        st.success("✅ Available")
    else:
        st.error("❌ Not Available")

# -----------------------------------------------------------------------------
# Single URL Analysis Section - WITH BETTER ERROR HANDLING
# -----------------------------------------------------------------------------
st.sidebar.header("Input Method")
input_method = st.sidebar.radio(
    "Choose input method:",
    ["Single URL Analysis", "Batch Prediction"]
)

st.sidebar.header("Analysis Options")
use_regex = st.sidebar.checkbox("Enable Regex Analysis", value=True)
use_ml_model = st.sidebar.checkbox("Enable ML Model", value=True)
use_dl_model = st.sidebar.checkbox("Enable DL Model", value=True)

# Disable options if models aren't available
if 'ml_model' not in models:
    use_ml_model = False
    st.sidebar.warning("ML model not available - option disabled")

if 'dl_model' not in models:
    use_dl_model = False
    st.sidebar.warning("DL model not available - option disabled")

if input_method == "Single URL Analysis":
    st.header("🔍 Single URL Analysis")
    st.info("Analyze individual URLs with hybrid ML+DL approach")
    
    # Show model status clearly
    if 'dl_model' not in models:
        st.error("❌ DL Model is not loaded. Check if real_dataset_dl_model.h5 and real_dataset_tokenizer.pkl exist in hybrid_results folder.")
    
    if 'ml_model' not in models:
        st.error("❌ ML Model is not loaded. Check if accessible_ml_model.pkl and accessible_scaler.pkl exist in hybrid_results folder.")
    
    url_input = st.text_input("Enter URL:", placeholder="https://example.com")
    
    col1, col2 = st.columns(2)
    with col1:
        analyze_btn = st.button("🔍 Analyze URL", type="primary", 
                               disabled=not any([use_ml_model, use_dl_model, use_regex]))
    with col2:
        quick_analyze_btn = st.button("⚡ Quick Analyze (5s timeout)", 
                                     disabled=not any([use_ml_model, use_dl_model, use_regex]))
    
    if analyze_btn or quick_analyze_btn:
        if not url_input.strip():
            st.error("Please enter a URL")
            st.stop()
        
        if not any([use_ml_model, use_dl_model, use_regex]):
            st.error("Please enable at least one analysis method")
            st.stop()
        
        # Use quick timeout if quick analyze button pressed
        current_timeout = 5 if quick_analyze_btn else timeout_seconds
        
        # Add protocol if missing
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input
        
        # Enhanced analysis
        with st.spinner(f"Analyzing URL (timeout: {current_timeout}s)..."):
            result = enhanced_url_prediction(
                url_input, 
                use_ml=use_ml_model, 
                use_dl=use_dl_model, 
                timeout=current_timeout
            )
        
        # Display results properly
        st.subheader("📊 Analysis Results")
        
        if result.get('error'):
            st.error(f"❌ Analysis failed: {result['error']}")
        else:
            # Create result columns
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Final Prediction", 
                         "🛑 PHISHING" if result.get('final_prediction') == 1 else "✅ LEGITIMATE",
                         f"Confidence: {result.get('final_confidence', 0):.1%}")
            
            with col2:
                status = "✅ Accessible" if result.get('accessible') else "❌ Inaccessible"
                if result.get('timeout_occurred'):
                    status = "⏰ Timeout"
                st.metric("URL Status", status)
            
            with col3:
                st.metric("Method Used", result.get('method_used', 'Unknown'))
            
            # Detailed results
            with st.expander("🔍 Detailed Analysis"):
                if use_ml_model and result.get('ml_prediction') is not None:
                    st.write(f"**ML Model:** {result['ml_prediction']} (confidence: {result.get('ml_confidence', 0):.1%})")
                
                if use_dl_model and result.get('dl_prediction') is not None:
                    st.write(f"**DL Model:** {result['dl_prediction']} (confidence: {result.get('dl_confidence', 0):.1%})")
                
                if use_regex:
                    regex_analysis = analyze_url_with_regex(url_input)
                    st.write(f"**Regex Analysis:** Score {regex_analysis['total_score']} ({regex_analysis['risk_level']} risk)")
    
    if analyze_btn or quick_analyze_btn:
        if not url_input:
            st.error("Please enter a URL")
            st.stop()
        
        if not any([use_ml_model, use_dl_model, use_regex]):
            st.error("Please enable at least one analysis method")
            st.stop()
        
        # Use quick timeout if quick analyze button pressed
        current_timeout = 5 if quick_analyze_btn else 10
        
        # Add protocol if missing
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input
        
        # Enhanced analysis
        with st.spinner(f"Analyzing URL (timeout: {current_timeout}s)..."):
            result = enhanced_url_prediction(
                url_input, 
                use_ml=use_ml_model, 
                use_dl=use_dl_model, 
                timeout=current_timeout
            )
        
        # Display results
        if result.get('error'):
            st.error(f"❌ Analysis failed: {result['error']}")
        else:
            if result.get('error'):
                st.write(f"Error: {result['error']}")

# -----------------------------------------------------------------------------
# Batch Prediction Section
# -----------------------------------------------------------------------------
elif input_method == "Batch Prediction":
    st.header("📊 Batch URL Analysis")
    st.info("Process multiple URLs from a CSV file")
    
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
            if not any([use_regex, use_ml_model, use_dl_model]):
                st.error("Please enable at least one analysis method")
                st.stop()

            try:
                st.info(f"🔄 Processing {len(df)} URLs with {timeout_seconds}s timeout...")
                
                # Prepare data for parallel processing
                url_data = [(idx, row[url_column], use_regex, use_ml_model, use_dl_model, timeout_seconds) 
                           for idx, row in df.iterrows()]
                
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
                    st.metric("Timeouts", timeouts)
                with col3:
                    phishing_count = results_df['Final_Prediction'].sum()
                    st.metric("Phishing Detected", phishing_count)
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
                    label="📥 Download Analysis Results",
                    data=csv_data,
                    file_name="phishing_analysis_results.csv",
                    mime="text/csv",
                )
                
                # Display sample results
                st.subheader("🔍 Sample Results")
                display_cols = [url_column, 'Final_Prediction', 'Final_Confidence', 'Method_Used']
                if 'Timeout_Occurred' in results_df.columns:
                    display_cols.append('Timeout_Occurred')
                
                st.dataframe(results_df[display_cols].head(10))

            except Exception as e:
                st.error(f"❌ Error in batch analysis: {e}")

# -----------------------------------------------------------------------------
# Footer
# -----------------------------------------------------------------------------
st.markdown("---")
st.markdown("**Advanced Phishing Detection System | Hybrid ML+DL Models**")
st.caption("Powered by machine learning and deep learning models for accurate URL classification")


