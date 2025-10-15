"""
Deep Learning Model for Phishing URL Detection
CNN-based approach for historical pattern analysis on CSV data
"""

import numpy as np
import pandas as pd
import pickle
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, classification_report
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Dropout, Embedding
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import warnings
warnings.filterwarnings('ignore')


class DeepLearningPhishingDetector:
    def __init__(self, output_dir="dl_model_results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        self.dl_model = None
        self.tokenizer = None

    def train_dl_model_on_dataset(self, train_path, test_path):
        """Train DL model on train/test CSV files"""
        print("\nTRAINING DL MODEL ON DATASET")
        print("=" * 50)
        
        try:
            # Load training data
            print(f"Loading training data from: {train_path}")
            train_df = pd.read_csv(train_path)
            print(f"Training data shape: {train_df.shape}")
            
            # Load testing data
            print(f"Loading testing data from: {test_path}")
            test_df = pd.read_csv(test_path)
            print(f"Testing data shape: {test_df.shape}")
            
            # Find URL and label columns
            def find_columns(df):
                url_col = None
                label_col = None
                
                for col in df.columns:
                    if 'url' in col.lower():
                        url_col = col
                    elif any(x in col.lower() for x in ['label', 'class', 'target']):
                        label_col = col
                
                return url_col, label_col
            
            train_url_col, train_label_col = find_columns(train_df)
            test_url_col, test_label_col = find_columns(test_df)
            
            if not train_url_col or not train_label_col:
                print("Could not find URL and label columns in training data")
                print(f"Available columns: {list(train_df.columns)}")
                return None, None, None
            
            if not test_url_col or not test_label_col:
                print("Could not find URL and label columns in testing data")
                print(f"Available columns: {list(test_df.columns)}")
                return None, None, None
            
            print(f"Using training columns: URL='{train_url_col}', Label='{train_label_col}'")
            print(f"Using testing columns: URL='{test_url_col}', Label='{test_label_col}'")
            
            # Extract URLs and labels
            X_train = train_df[train_url_col].fillna('').values
            y_train = train_df[train_label_col].values
            X_test = test_df[test_url_col].fillna('').values  
            y_test = test_df[test_label_col].values
            
            # Convert labels to binary if needed
            def convert_labels(labels):
                if set(labels).issubset({0, 1}):
                    return labels.astype(int)
                elif set(labels).issubset({'benign', 'malicious', 'phishing'}):
                    return (pd.Series(labels).str.lower().isin(['malicious', 'phishing'])).astype(int).values
                elif set(labels).issubset({-1, 1}):
                    return (labels == 1).astype(int)
                else:
                    # Try to infer from string content
                    labels_str = pd.Series(labels).astype(str).str.lower()
                    is_malicious = labels_str.str.contains('malicious|phishing|phish|bad|evil|1', na=False)
                    return is_malicious.astype(int).values
            
            y_train = convert_labels(y_train)
            y_test = convert_labels(y_test)
            
            print(f"Training set: {len(X_train):,} URLs")
            print(f"Test set: {len(X_test):,} URLs")
            print(f"Training label distribution: {np.bincount(y_train)}")
            print(f"Test label distribution: {np.bincount(y_test)}")
            
            # Tokenize URLs
            self.tokenizer = Tokenizer(char_level=True, num_words=100)
            self.tokenizer.fit_on_texts(X_train)
            
            X_train_seq = self.tokenizer.texts_to_sequences(X_train)
            X_test_seq = self.tokenizer.texts_to_sequences(X_test)
            
            max_length = 200
            X_train_pad = pad_sequences(X_train_seq, maxlen=max_length, padding='post')
            X_test_pad = pad_sequences(X_test_seq, maxlen=max_length, padding='post')
            
            print(f"Tokenized sequences - Train: {X_train_pad.shape}, Test: {X_test_pad.shape}")
            
            # Create CNN model
            self.dl_model = Sequential([
                Embedding(100, 128, input_length=max_length),
                Conv1D(128, 5, activation='relu'),
                MaxPooling1D(2),
                Dropout(0.3),
                Conv1D(64, 5, activation='relu'),
                MaxPooling1D(2),
                Dropout(0.3),
                Conv1D(32, 3, activation='relu'),
                MaxPooling1D(2),
                Dropout(0.3),
                Flatten(),
                Dense(128, activation='relu'),
                Dropout(0.5),
                Dense(64, activation='relu'),
                Dropout(0.5),
                Dense(1, activation='sigmoid')
            ])
            
            self.dl_model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy', 'precision', 'recall']
            )
            
            print("\nCNN Model Architecture:")
            self.dl_model.summary()
            
            # Train with callbacks
            callbacks = [
                EarlyStopping(patience=10, restore_best_weights=True, verbose=1),
                ReduceLROnPlateau(patience=5, factor=0.5, verbose=1)
            ]
            
            print("\nTraining CNN model on dataset...")
            import time
            start_time = time.time()
            
            history = self.dl_model.fit(
                X_train_pad, y_train,
                epochs=50,
                batch_size=64,
                validation_split=0.2,
                callbacks=callbacks,
                verbose=1
            )
            
            training_time = time.time() - start_time
            
            # Evaluate on test set
            print("\nEvaluating on test set...")
            y_pred_prob = self.dl_model.predict(X_test_pad)
            y_pred = (y_pred_prob > 0.5).astype(int).flatten()
            
            accuracy = accuracy_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred, average='binary', pos_label=1, zero_division=0)
            precision = precision_score(y_test, y_pred, average='binary', pos_label=1, zero_division=0)
            recall = recall_score(y_test, y_pred, average='binary', pos_label=1, zero_division=0)
            
            print(f"\nDL MODEL PERFORMANCE:")
            print(f"Training time: {training_time:.1f}s")
            print(f"Training samples: {len(X_train):,}")
            print(f"Test samples: {len(X_test):,}")
            print(f"Test Accuracy: {accuracy:.4f}")
            print(f"Test F1 Score: {f1:.4f}")
            print(f"Test Precision: {precision:.4f}")
            print(f"Test Recall: {recall:.4f}")
            
            # Detailed classification report
            print(f"\nDetailed Classification Report:")
            print(classification_report(y_test, y_pred, zero_division=0))
            
            # Save model
            model_path = os.path.join(self.output_dir, "phishing_dl_model.h5")
            tokenizer_path = os.path.join(self.output_dir, "dl_tokenizer.pkl")
            
            self.dl_model.save(model_path)
            with open(tokenizer_path, 'wb') as f:
                pickle.dump(self.tokenizer, f)
            
            print(f"\nModel saved to: {model_path}")
            print(f"Tokenizer saved to: {tokenizer_path}")
            
            return accuracy, f1, history
            
        except FileNotFoundError as e:
            print(f"File not found: {e}")
            return None, None, None
        except Exception as e:
            print(f"Error training DL model: {e}")
            import traceback
            traceback.print_exc()
            return None, None, None

    def predict(self, url):
        """Predict single URL"""
        if self.dl_model is None or self.tokenizer is None:
            print("Model not trained. Please train the model first.")
            return None
        
        try:
            url_seq = self.tokenizer.texts_to_sequences([url])
            url_pad = pad_sequences(url_seq, maxlen=200, padding='post')
            
            dl_prob = self.dl_model.predict(url_pad, verbose=0)[0][0]
            dl_pred = 1 if dl_prob > 0.5 else 0
            
            return {
                'url': url,
                'prediction': 'PHISHING' if dl_pred == 1 else 'BENIGN',
                'confidence': float(max(dl_prob, 1-dl_prob)),
                'phishing_probability': float(dl_prob)
            }
        except Exception as e:
            print(f"Error predicting URL: {e}")
            return None

    def batch_predict(self, urls):
        """Predict multiple URLs"""
        results = []
        for url in urls:
            result = self.predict(url)
            if result:
                results.append(result)
        return results


def main():
    """Main execution function"""
    print("DEEP LEARNING PHISHING URL DETECTOR")
    print("=" * 60)
    print("CNN-based model for URL pattern analysis")
    print("=" * 60)
    
    # Your dataset paths - UPDATE THESE PATHS
    train_csv_path = "Train.csv"
    test_csv_path = "Test.csv"
    
    # Create detector
    detector = DeepLearningPhishingDetector(output_dir="dl_model_results")
    
    try:
        # Train model
        accuracy, f1, history = detector.train_dl_model_on_dataset(
            train_path=train_csv_path,
            test_path=test_csv_path
        )
        
        if accuracy is not None:
            print("\n" + "=" * 60)
            print("TRAINING COMPLETED SUCCESSFULLY!")
            print("=" * 60)
            
            # Test with sample URLs
            print("\nTesting with sample URLs:")
            test_urls = [
                "https://www.google.com",
                "https://secure-login-verify.com",
                "https://github.com",
                "http://account-update.tk",
                "https://paypal.com",
            ]
            
            predictions = detector.batch_predict(test_urls)
            
            for pred in predictions:
                print(f"\nURL: {pred['url']}")
                print(f"Prediction: {pred['prediction']}")
                print(f"Confidence: {pred['confidence']:.3f}")
                print(f"Phishing Probability: {pred['phishing_probability']:.3f}")
        
    except KeyboardInterrupt:
        print("\nProcess interrupted by user")
    except Exception as e:
        print(f"\nTraining failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()