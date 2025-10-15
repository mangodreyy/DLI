"""
Train and Test ML Model with Fresh Dataset
Uses the collected 30K fresh URLs with real features
Expected: 85-92% accuracy (vs old 68%)
"""

import numpy as np
import pandas as pd
import pickle
import os
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, StackingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')


def load_datasets(train_path, val_path):
    """Load training and validation datasets"""
    print("=" * 70)
    print("LOADING FRESH DATASETS")
    print("=" * 70)
    
    # Load training data
    print(f"Loading training data from: {train_path}")
    with open(train_path, 'rb') as f:
        train_data = pickle.load(f)
    
    X_train = train_data['X']
    y_train = train_data['y']
    
    print(f"✓ Training set loaded: {len(X_train):,} samples")
    print(f"  • Features shape: {X_train.shape}")
    print(f"  • Label distribution: {np.bincount(y_train)}")
    
    # Load validation data
    print(f"\nLoading validation data from: {val_path}")
    with open(val_path, 'rb') as f:
        val_data = pickle.load(f)
    
    X_val = val_data['X']
    y_val = val_data['y']
    
    print(f"✓ Validation set loaded: {len(X_val):,} samples")
    print(f"  • Features shape: {X_val.shape}")
    print(f"  • Label distribution: {np.bincount(y_val)}")
    
    return X_train, y_train, X_val, y_val


def train_model(X_train, y_train, output_dir):
    """Train enhanced ML model"""
    print("\n" + "=" * 70)
    print("TRAINING MODEL ON FRESH DATA")
    print("=" * 70)
    
    # Scale features
    print("Scaling features with RobustScaler...")
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Build enhanced ensemble
    print("\nBuilding Enhanced Stacking Ensemble Model...")
    print("Base models:")
    print("  1. Gradient Boosting (200 estimators)")
    print("  2. Random Forest (300 estimators, balanced)")
    print("  3. MLP Neural Network #1 (256→128→64)")
    print("  4. MLP Neural Network #2 (128→64→32)")
    print("Meta learner: Logistic Regression (balanced)")
    
    base_models = [
        ('gb', GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=5,
            subsample=0.8,
            random_state=42,
            verbose=0
        )),
        ('rf', RandomForestClassifier(
            n_estimators=300,
            max_depth=15,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
            verbose=0
        )),
        ('mlp1', MLPClassifier(
            hidden_layer_sizes=(256, 128, 64),
            max_iter=2000,
            early_stopping=True,
            learning_rate='adaptive',
            learning_rate_init=0.001,
            alpha=0.001,
            random_state=42,
            verbose=False
        )),
        ('mlp2', MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            max_iter=2000,
            early_stopping=True,
            learning_rate='adaptive',
            alpha=0.001,
            random_state=43,
            verbose=False
        ))
    ]
    
    meta_learner = LogisticRegression(
        C=1.0,
        max_iter=2000,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    
    model = StackingClassifier(
        estimators=base_models,
        final_estimator=meta_learner,
        cv=5,
        stack_method='predict_proba',
        n_jobs=-1,
        verbose=1
    )
    
    # Train
    print("\n🚀 Training model (this may take 2-5 minutes)...")
    import time
    start_time = time.time()
    
    model.fit(X_train_scaled, y_train)
    
    training_time = time.time() - start_time
    print(f"\n✓ Training completed in {training_time:.1f}s ({training_time/60:.1f} minutes)")
    
    # Save model and scaler
    os.makedirs(output_dir, exist_ok=True)
    
    model_path = os.path.join(output_dir, "trained_ML__model.pkl")
    scaler_path = os.path.join(output_dir, "trained_ML_scaler.pkl")
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    
    print(f"\n💾 Model saved:")
    print(f"  • {model_path}")
    print(f"  • {scaler_path}")
    
    return model, scaler, training_time


def evaluate_model(model, scaler, X_val, y_val):
    """Evaluate model on validation set"""
    print("\n" + "=" * 70)
    print("MODEL EVALUATION ON VALIDATION SET")
    print("=" * 70)
    
    # Scale validation data
    X_val_scaled = scaler.transform(X_val)
    
    # Predict
    print("Making predictions...")
    y_pred = model.predict(X_val_scaled)
    y_pred_proba = model.predict_proba(X_val_scaled)
    
    # Calculate metrics
    accuracy = accuracy_score(y_val, y_pred)
    f1 = f1_score(y_val, y_pred, average='binary', pos_label=1)
    precision = precision_score(y_val, y_pred, average='binary', pos_label=1)
    recall = recall_score(y_val, y_pred, average='binary', pos_label=1)
    
    print(f"\n📊 PERFORMANCE METRICS:")
    print(f"  Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    
    # Confusion matrix
    cm = confusion_matrix(y_val, y_pred)
    tn, fp, fn, tp = cm.ravel()
    specificity = tn / (tn + fp)
    
    print(f"\n📋 Confusion Matrix:")
    print(f"                Predicted")
    print(f"              Benign  Phishing")
    print(f"Actual Benign    {cm[0][0]:5d}    {cm[0][1]:5d}")
    print(f"     Phishing    {cm[1][0]:5d}    {cm[1][1]:5d}")
    
    print(f"\n📈 Detailed Metrics:")
    print(f"  True Positives:  {tp:,} (Phishing correctly detected)")
    print(f"  True Negatives:  {tn:,} (Benign correctly detected)")
    print(f"  False Positives: {fp:,} (Benign wrongly flagged)")
    print(f"  False Negatives: {fn:,} (Phishing missed)")
    print(f"  Specificity:     {specificity:.4f}")
    
    # Detection rates
    phishing_detection_rate = tp / (tp + fn) * 100
    benign_detection_rate = tn / (tn + fp) * 100
    
    print(f"\n🎯 Detection Rates:")
    print(f"  Phishing detection: {phishing_detection_rate:.1f}% ({tp}/{tp+fn})")
    print(f"  Benign detection:   {benign_detection_rate:.1f}% ({tn}/{tn+fp})")
    
    print(f"\n📄 Classification Report:")
    print(classification_report(y_val, y_pred, target_names=['Benign', 'Phishing'], digits=4))
    
    return {
        'accuracy': accuracy,
        'f1_score': f1,
        'precision': precision,
        'recall': recall,
        'specificity': specificity,
        'confusion_matrix': cm,
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn
    }


def test_sample_urls(model, scaler):
    """Test model with sample URLs"""
    print("\n" + "=" * 70)
    print("TESTING WITH SAMPLE URLs")
    print("=" * 70)
    
    from feature import FeatureExtraction
    
    test_cases = [
        ("https://www.google.com", 0, "Google"),
        ("https://www.paypal.com", 0, "PayPal"),
        ("https://github.com", 0, "GitHub"),
        ("https://www.amazon.com", 0, "Amazon"),
        ("https://www.microsoft.com", 0, "Microsoft"),
    ]
    
    print("\nTesting 5 legitimate URLs...\n")
    
    correct = 0
    total = 0
    
    for url, expected, name in test_cases:
        try:
            # Extract features
            extractor = FeatureExtraction(url)
            features = extractor.getFeaturesList()
            
            if features and len(features) == 30:
                # Scale and predict
                features_scaled = scaler.transform([features])
                prediction = model.predict(features_scaled)[0]
                probability = model.predict_proba(features_scaled)[0]
                
                is_correct = (prediction == expected)
                correct += is_correct
                total += 1
                
                predicted_label = "BENIGN" if prediction == 0 else "PHISHING"
                expected_label = "BENIGN" if expected == 0 else "PHISHING"
                confidence = max(probability)
                
                status = "✅" if is_correct else "❌"
                
                print(f"{status} {name}")
                print(f"   Expected: {expected_label} | Predicted: {predicted_label}")
                print(f"   Confidence: {confidence:.2%}")
                print(f"   Probabilities: Benign={probability[0]:.2%}, Phishing={probability[1]:.2%}\n")
            else:
                print(f"⚠️  {name} - Could not extract features\n")
        
        except Exception as e:
            print(f"❌ {name} - Error: {str(e)}\n")
    
    if total > 0:
        print(f"Sample test accuracy: {correct}/{total} ({correct/total*100:.1f}%)")


def compare_with_old_model():
    """Show comparison with old model"""
    print("\n" + "=" * 70)
    print("COMPARISON: OLD vs NEW MODEL")
    print("=" * 70)
    
    comparison = {
        'Dataset': ['Old (Dead URLs)', 'New (Fresh URLs)'],
        'URLs': ['47,000', '30,062'],
        'Accessible': ['~20% dead', '100% accessible'],
        'Features': ['Default values', 'Real HTML/scripts'],
        'Accuracy': ['68.49%', 'YOUR_RESULT'],
        'F1 Score': ['0.6851', 'YOUR_RESULT'],
        'Recall': ['68.55%', 'YOUR_RESULT']
    }
    
    print("\n| Metric      | Old Model    | New Model    | Improvement |")
    print("|-------------|--------------|--------------|-------------|")
    print("| Dataset     | 47K dead URLs| 30K fresh    | Quality ✓   |")
    print("| Accessible  | ~20%         | 100%         | +400% ✓     |")
    print("| Features    | Defaults     | Real HTML    | Much better✓|")
    print("| Accuracy    | 68.49%       | [SEE ABOVE]  | Expected +15-25% |")
    print("| Recall      | 68.55%       | [SEE ABOVE]  | Expected +10-20% |")


def main():
    """Main execution"""
    print("=" * 70)
    print("TRAIN & TEST MODEL WITH FRESH DATASET")
    print("=" * 70)
    print("Dataset: 30,062 fresh URLs with real features")
    print("Expected: 85-92% accuracy (vs old 68%)")
    print("=" * 70)
    
    # Paths
    train_path = "streaming_dataset/train_dataset.pkl"
    val_path = "streaming_dataset/val_dataset.pkl"
    output_dir = "fresh_model_results"
    
    try:
        # Load datasets
        X_train, y_train, X_val, y_val = load_datasets(train_path, val_path)
        
        # Train model
        model, scaler, training_time = train_model(X_train, y_train, output_dir)
        
        # Evaluate model
        results = evaluate_model(model, scaler, X_val, y_val)
        
        # Test with sample URLs
        test_sample_urls(model, scaler)
        
        # Show comparison
        compare_with_old_model()
        
        # Final summary
        print("\n" + "=" * 70)
        print("🎉 TRAINING & TESTING COMPLETE!")
        print("=" * 70)
        
        print(f"\n📊 Final Results:")
        print(f"  Training samples: {len(X_train):,}")
        print(f"  Validation samples: {len(X_val):,}")
        print(f"  Training time: {training_time:.1f}s")
        print(f"  ")
        print(f"  ✓ Accuracy:  {results['accuracy']:.4f} ({results['accuracy']*100:.2f}%)")
        print(f"  ✓ F1 Score:  {results['f1_score']:.4f}")
        print(f"  ✓ Precision: {results['precision']:.4f}")
        print(f"  ✓ Recall:    {results['recall']:.4f}")
        
        improvement = (results['accuracy'] - 0.6849) * 100
        print(f"\n🚀 Improvement over old model:")
        print(f"  Accuracy: +{improvement:.2f} percentage points")
        print(f"  (68.49% → {results['accuracy']*100:.2f}%)")
        
        if results['accuracy'] >= 0.85:
            print(f"\n🏆 EXCELLENT! Achieved target accuracy of 85%+")
        elif results['accuracy'] >= 0.75:
            print(f"\n✅ GOOD! Significant improvement from 68%")
        else:
            print(f"\n⚠️  Below expected - may need more data or tuning")
        
        print(f"\n📁 Model saved to: {output_dir}/")
        print(f"  • fresh_phishing_model.pkl")
        print(f"  • fresh_phishing_scaler.pkl")
        
        # Save summary
        summary_path = os.path.join(output_dir, "training_summary.pkl")
        with open(summary_path, 'wb') as f:
            pickle.dump({
                'results': results,
                'training_time': training_time,
                'train_samples': len(X_train),
                'val_samples': len(X_val)
            }, f)
        
        print(f"  • training_summary.pkl")
        
    except FileNotFoundError as e:
        print(f"\n❌ Error: Dataset file not found")
        print(f"Make sure these files exist:")
        print(f"  • {train_path}")
        print(f"  • {val_path}")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()