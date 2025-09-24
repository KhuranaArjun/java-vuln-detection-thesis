#!/usr/bin/env python3
"""
Multi-Architecture Java Vulnerability Detection Comparison
Based on your working BiLSTM script with identical data preprocessing
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Tuple
import pickle
import logging
from collections import Counter
import time

# Deep Learning imports
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import (
    LSTM, Dense, Embedding, Dropout, Bidirectional, Conv1D, GlobalMaxPooling1D,
    MultiHeadAttention, LayerNormalization, GlobalAveragePooling1D, Input,
    Concatenate, Add, BatchNormalization
)
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
from tensorflow.keras.optimizers import Adam
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.utils.class_weight import compute_class_weight

# Traditional ML
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score

# Word2Vec for embeddings
from gensim.models import Word2Vec
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MultiArchitectureJavaClassifier:
    def __init__(self, dataset_path: str, models_output_dir: str):
        self.dataset_path = Path(dataset_path)
        self.models_output_dir = Path(models_output_dir)
        self.models_output_dir.mkdir(parents=True, exist_ok=True)
        
        # EXACT SAME PARAMETERS AS YOUR WORKING BiLSTM
        self.max_sequence_length = 128
        self.embedding_dim = 200
        self.vocab_size = 15000
        self.lstm_units_1 = 128
        self.lstm_units_2 = 64
        self.dense_units = 64
        self.dropout_rate = 0.3
        self.batch_size = 64
        self.max_epochs = 50
        self.learning_rate = 0.001
        
        # EXACT SAME VULNERABILITY CLASSES AS YOUR WORKING SCRIPT
        self.vulnerability_classes = {
            'SQL_INJECTION': 0,
            'XSS': 1, 
            'PATH_TRAVERSAL': 2,
            'COMMAND_INJECTION': 3,
            'XXE': 4,
            'DESERIALIZATION': 5,
            'CSRF': 6,
            'ACCESS_CONTROL': 7,
            'INPUT_VALIDATION': 8,
            'CONFIGURATION_ERROR': 9,
            'CRYPTOGRAPHIC_ISSUE': 10,
            'OTHER_SECURITY': 11
        }
        
        self.class_to_name = {v: k for k, v in self.vulnerability_classes.items()}
        
        # EXACT SAME PATTERNS AS YOUR WORKING SCRIPT
        self.vulnerability_patterns = {
            'SQL_INJECTION': [
                'sql', 'query', 'statement', 'preparedstatement', 'execute', 
                'select', 'insert', 'update', 'delete', 'union', 'injection'
            ],
            'XSS': [
                'xss', 'script', 'javascript', 'html', 'dom', 'innerHTML', 
                'eval', 'document.write', 'cross-site', 'scripting'
            ],
            'PATH_TRAVERSAL': [
                'path', 'file', 'directory', '..', 'traversal', 'filesystem',
                'getresource', 'inputstream', 'fileoutput', 'fileinput'
            ],
            'COMMAND_INJECTION': [
                'runtime', 'exec', 'processbuilder', 'command', 'shell',
                'system', 'bash', 'cmd', 'injection'
            ],
            'XXE': [
                'xml', 'xmlreader', 'documentbuilder', 'sax', 'external',
                'entity', 'dtd', 'xmlinput'
            ],
            'DESERIALIZATION': [
                'deserialize', 'objectinputstream', 'readobject', 'serialize',
                'jackson', 'gson', 'unmarshall'
            ],
            'CSRF': [
                'csrf', 'token', 'session', 'cross-site', 'request', 'forgery',
                'referer', 'origin'
            ],
            'ACCESS_CONTROL': [
                'permission', 'role', 'authorization', 'access', 'security',
                'privilege', 'authenticate', 'authorize'
            ],
            'INPUT_VALIDATION': [
                'validate', 'sanitize', 'input', 'parameter', 'request',
                'filter', 'escape', 'clean'
            ],
            'CONFIGURATION_ERROR': [
                'config', 'properties', 'setting', 'default', 'hardcoded',
                'password', 'key', 'secret'
            ],
            'CRYPTOGRAPHIC_ISSUE': [
                'crypto', 'encrypt', 'decrypt', 'hash', 'random', 'cipher',
                'ssl', 'tls', 'certificate', 'key'
            ]
        }
        
        # Data storage
        self.word2vec_model = None
        self.tokenizer_vocab = {}
        self.dataset = None
        self.X_train = None
        self.X_val = None
        self.X_test = None
        self.y_train = None
        self.y_val = None
        self.y_test = None
        self.embedding_matrix = None
        self.results = {}
        
        # For Random Forest
        self.tfidf = None
        self.X_train_tfidf = None
        self.X_val_tfidf = None
        self.X_test_tfidf = None

    # EXACT SAME DATA PROCESSING METHODS AS YOUR WORKING SCRIPT
    def load_dataset(self) -> Dict:
        """Load the dataset and classify samples - EXACT COPY"""
        logger.info(f"Loading dataset from {self.dataset_path}")
        
        with open(self.dataset_path, 'r') as f:
            dataset = json.load(f)
            
        logger.info(f"Dataset loaded: {dataset['metadata']['total_samples']} total samples")
        logger.info(f"Train: {len(dataset['train'])}, Val: {len(dataset['validation'])}, Test: {len(dataset['test'])}")
        
        # Classify samples
        self.classify_samples(dataset['train'])
        self.classify_samples(dataset['validation'])  
        self.classify_samples(dataset['test'])
        
        self.dataset = dataset
        return dataset
    
    def classify_sample(self, sample: Dict) -> str:
        """Classify a single sample based on code patterns - EXACT COPY"""
        vulnerable_code = sample.get('vulnerable_code', '').lower()
        fixed_code = sample.get('fixed_code', '').lower()
        
        # Check existing classification first
        if 'vulnerability_type' in sample and sample['vulnerability_type'] != 'Unknown':
            existing_type = sample['vulnerability_type'].upper().replace(' ', '_')
            if existing_type in self.vulnerability_classes:
                return existing_type
        
        # Combine vulnerable and fixed code for pattern matching
        combined_code = vulnerable_code + ' ' + fixed_code
        
        # Score each vulnerability type
        type_scores = {}
        for vuln_type, patterns in self.vulnerability_patterns.items():
            score = sum(1 for pattern in patterns if pattern in combined_code)
            if score > 0:
                type_scores[vuln_type] = score
        
        # Return the highest scoring type, or OTHER_SECURITY if no matches
        if type_scores:
            return max(type_scores.items(), key=lambda x: x[1])[0]
        else:
            return 'OTHER_SECURITY'
    
    def classify_samples(self, samples: List[Dict]):
        """Classify all samples in a dataset split - EXACT COPY"""
        logger.info(f"Classifying {len(samples)} samples...")
        
        classified_counts = Counter()
        
        for sample in samples:
            vulnerability_type = self.classify_sample(sample)
            sample['vulnerability_type'] = vulnerability_type
            sample['vulnerability_class'] = self.vulnerability_classes[vulnerability_type]
            classified_counts[vulnerability_type] += 1
        
        logger.info("Classification distribution:")
        for vuln_type, count in classified_counts.most_common():
            percentage = (count / len(samples)) * 100
            logger.info(f"  {vuln_type}: {count} ({percentage:.1f}%)")
    
    def tokenize_java_code(self, code: str) -> List[str]:
        """Tokenize Java code - EXACT COPY"""
        if not code:
            return []
            
        # Clean code
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'\s+', ' ', code)
        
        # Java-specific tokenization
        tokens = re.findall(r'[a-zA-Z_$][a-zA-Z0-9_$]*|[0-9]+|[^\w\s]', code)
        
        # Filter and normalize
        filtered_tokens = []
        for token in tokens:
            token = token.strip().lower()
            if token and len(token) > 0:
                filtered_tokens.append(token)
                
        return filtered_tokens
    
    def extract_code_corpus(self, samples: List[Dict]) -> List[List[str]]:
        """Extract code corpus for Word2Vec training - EXACT COPY"""
        logger.info("Extracting code corpus for Word2Vec training...")
        
        corpus = []
        
        for sample in samples:
            vulnerable_code = sample.get('vulnerable_code', '')
            fixed_code = sample.get('fixed_code', '')
            
            vulnerable_tokens = self.tokenize_java_code(vulnerable_code)
            fixed_tokens = self.tokenize_java_code(fixed_code)
            
            if vulnerable_tokens:
                corpus.append(vulnerable_tokens)
            if fixed_tokens:
                corpus.append(fixed_tokens)
                
        logger.info(f"Extracted {len(corpus)} code sequences for Word2Vec training")
        return corpus
    
    def train_word2vec_embeddings(self, samples: List[Dict]) -> Word2Vec:
        """Train Word2Vec embeddings - EXACT COPY"""
        logger.info("Training Word2Vec embeddings...")
        
        corpus = self.extract_code_corpus(samples)
        
        word2vec_model = Word2Vec(
            sentences=corpus,
            vector_size=self.embedding_dim,
            window=5,
            min_count=2,
            workers=4,
            epochs=10,
            sg=1
        )
        
        logger.info(f"Word2Vec model trained with vocabulary size: {len(word2vec_model.wv.key_to_index)}")
        
        self.word2vec_model = word2vec_model
        return word2vec_model
    
    def create_vocabulary(self, samples: List[Dict]) -> Dict[str, int]:
        """Create vocabulary mapping - EXACT COPY"""
        logger.info("Creating vocabulary mapping...")
        
        token_freq = Counter()
        
        for sample in samples:
            vulnerable_code = sample.get('vulnerable_code', '')
            fixed_code = sample.get('fixed_code', '')
            
            vulnerable_tokens = self.tokenize_java_code(vulnerable_code)
            fixed_tokens = self.tokenize_java_code(fixed_code)
            
            token_freq.update(vulnerable_tokens)
            token_freq.update(fixed_tokens)
        
        # Create vocabulary
        vocab = {'<PAD>': 0, '<UNK>': 1}
        
        for token, freq in token_freq.most_common(self.vocab_size - 2):
            vocab[token] = len(vocab)
            
        logger.info(f"Vocabulary created with {len(vocab)} tokens")
        
        self.tokenizer_vocab = vocab
        return vocab
    
    def create_embedding_matrix(self) -> np.ndarray:
        """Create embedding matrix from Word2Vec model - EXACT COPY"""
        logger.info("Creating embedding matrix from Word2Vec...")
        
        embedding_matrix = np.zeros((len(self.tokenizer_vocab), self.embedding_dim))
        
        for token, idx in self.tokenizer_vocab.items():
            if token in ['<PAD>', '<UNK>']:
                continue
                
            try:
                embedding_vector = self.word2vec_model.wv[token]
                embedding_matrix[idx] = embedding_vector
            except KeyError:
                embedding_matrix[idx] = np.random.normal(size=self.embedding_dim)
                
        logger.info(f"Embedding matrix created: {embedding_matrix.shape}")
        self.embedding_matrix = embedding_matrix
        return embedding_matrix
    
    def prepare_sequences(self, samples: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare sequences for training - EXACT COPY"""
        logger.info(f"Preparing sequences for {len(samples)} samples...")
        
        sequences = []
        labels = []
        
        for sample in samples:
            # Get vulnerability class
            vuln_class = sample.get('vulnerability_class', self.vulnerability_classes['OTHER_SECURITY'])
            
            # Use vulnerable code (primary focus)
            vulnerable_code = sample.get('vulnerable_code', '')
            if vulnerable_code:
                tokens = self.tokenize_java_code(vulnerable_code)
                
                if tokens:
                    token_indices = [
                        self.tokenizer_vocab.get(token, self.tokenizer_vocab['<UNK>'])
                        for token in tokens[:self.max_sequence_length]
                    ]
                    
                    sequences.append(token_indices)
                    labels.append(vuln_class)
        
        # Pad sequences
        X = pad_sequences(sequences, maxlen=self.max_sequence_length, padding='post', truncating='post')
        y = np.array(labels)
        
        logger.info(f"Prepared {len(X)} sequences")
        return X, y
    
    def prepare_data(self):
        """Prepare all data for training"""
        logger.info("Preparing data for all architectures...")
        
        # Load and classify dataset
        dataset = self.load_dataset()
        
        # Combine all samples for Word2Vec training
        all_samples = dataset['train'] + dataset['validation'] + dataset['test']
        
        # Train embeddings and create vocabulary
        self.train_word2vec_embeddings(all_samples)
        self.create_vocabulary(all_samples)
        self.create_embedding_matrix()
        
        # Prepare sequence data for neural networks
        self.X_train, self.y_train = self.prepare_sequences(dataset['train'])
        self.X_val, self.y_val = self.prepare_sequences(dataset['validation'])
        self.X_test, self.y_test = self.prepare_sequences(dataset['test'])
        
        # Prepare text data for Random Forest
        self.prepare_tfidf_data(dataset)
        
        logger.info(f"Data prepared - Train: {len(self.X_train)}, Val: {len(self.X_val)}, Test: {len(self.X_test)}")
    
    def prepare_tfidf_data(self, dataset):
        """Prepare TF-IDF features for Random Forest"""
        logger.info("Preparing TF-IDF features for Random Forest...")
        
        def extract_text(samples):
            texts = []
            for sample in samples:
                vulnerable_code = sample.get('vulnerable_code', '')
                texts.append(vulnerable_code)
            return texts
        
        train_texts = extract_text(dataset['train'])
        val_texts = extract_text(dataset['validation'])
        test_texts = extract_text(dataset['test'])
        
        # Create TF-IDF features
        self.tfidf = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words='english'
        )
        
        self.X_train_tfidf = self.tfidf.fit_transform(train_texts)
        self.X_val_tfidf = self.tfidf.transform(val_texts)
        self.X_test_tfidf = self.tfidf.transform(test_texts)
    
    # MODEL ARCHITECTURES
    def build_bilstm_model(self) -> tf.keras.Model:
        """Build BiLSTM model - YOUR EXACT ARCHITECTURE"""
        logger.info("Building BiLSTM model (your exact architecture)...")
        
        num_classes = len(self.vulnerability_classes)
        
        model = Sequential([
            Embedding(
                input_dim=len(self.tokenizer_vocab),
                output_dim=self.embedding_dim,
                weights=[self.embedding_matrix],
                trainable=True,
                name='embedding'
            ),
            
            Bidirectional(LSTM(
                self.lstm_units_1,
                return_sequences=True,
                dropout=self.dropout_rate,
                recurrent_dropout=self.dropout_rate,
                name='lstm_1'
            )),
            
            Bidirectional(LSTM(
                self.lstm_units_2,
                return_sequences=False,
                dropout=self.dropout_rate,
                recurrent_dropout=self.dropout_rate,
                name='lstm_2'
            )),
            
            Dense(self.dense_units, activation='relu', name='dense_1'),
            Dropout(self.dropout_rate),
            
            Dense(self.dense_units // 2, activation='relu', name='dense_2'),
            Dropout(self.dropout_rate),
            
            Dense(num_classes, activation='softmax', name='output')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=self.learning_rate),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def build_cnn_model(self) -> tf.keras.Model:
        """Build CNN model for pattern detection"""
        logger.info("Building CNN model...")
        
        num_classes = len(self.vulnerability_classes)
        
        model = Sequential([
            Embedding(
                input_dim=len(self.tokenizer_vocab),
                output_dim=self.embedding_dim,
                weights=[self.embedding_matrix],
                trainable=True
            ),
            
            # Multiple CNN layers with different filter sizes
            Conv1D(128, 3, activation='relu', padding='same'),
            BatchNormalization(),
            Dropout(0.3),
            
            Conv1D(256, 5, activation='relu', padding='same'),
            BatchNormalization(),
            Dropout(0.3),
            
            Conv1D(128, 7, activation='relu', padding='same'),
            GlobalMaxPooling1D(),
            
            Dense(128, activation='relu'),
            Dropout(0.5),
            
            Dense(64, activation='relu'),
            Dropout(0.3),
            
            Dense(num_classes, activation='softmax')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=self.learning_rate),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def build_transformer_model(self) -> tf.keras.Model:
        """Build simplified Transformer model"""
        logger.info("Building Transformer model...")
        
        num_classes = len(self.vulnerability_classes)
        
        inputs = Input(shape=(self.max_sequence_length,))
        
        # Embedding
        embedding = Embedding(
            input_dim=len(self.tokenizer_vocab),
            output_dim=self.embedding_dim,
            weights=[self.embedding_matrix],
            trainable=True
        )(inputs)
        
        # Multi-head attention
        attention = MultiHeadAttention(
            num_heads=4, 
            key_dim=self.embedding_dim // 4
        )(embedding, embedding)
        
        # Add & Norm
        attention = Add()([embedding, attention])
        attention = LayerNormalization()(attention)
        
        # Global pooling
        pooled = GlobalAveragePooling1D()(attention)
        
        # Classification head
        dense1 = Dense(128, activation='relu')(pooled)
        dense1 = Dropout(0.3)(dense1)
        dense2 = Dense(64, activation='relu')(dense1)
        dense2 = Dropout(0.3)(dense2)
        
        outputs = Dense(num_classes, activation='softmax')(dense2)
        
        model = Model(inputs=inputs, outputs=outputs)
        
        model.compile(
            optimizer=Adam(learning_rate=self.learning_rate),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def build_hybrid_cnn_lstm_model(self) -> tf.keras.Model:
        """Build hybrid CNN+LSTM model"""
        logger.info("Building Hybrid CNN+LSTM model...")
        
        num_classes = len(self.vulnerability_classes)
        
        inputs = Input(shape=(self.max_sequence_length,))
        
        # Shared embedding
        embedding = Embedding(
            input_dim=len(self.tokenizer_vocab),
            output_dim=self.embedding_dim,
            weights=[self.embedding_matrix],
            trainable=True
        )(inputs)
        
        # CNN branch
        cnn_branch = Conv1D(64, 3, activation='relu', padding='same')(embedding)
        cnn_branch = Conv1D(64, 5, activation='relu', padding='same')(cnn_branch)
        cnn_branch = GlobalMaxPooling1D()(cnn_branch)
        cnn_branch = Dense(32, activation='relu')(cnn_branch)
        
        # LSTM branch
        lstm_branch = LSTM(64, return_sequences=False)(embedding)
        lstm_branch = Dense(32, activation='relu')(lstm_branch)
        
        # Combine branches
        combined = Concatenate()([cnn_branch, lstm_branch])
        combined = Dense(64, activation='relu')(combined)
        combined = Dropout(0.3)(combined)
        
        outputs = Dense(num_classes, activation='softmax')(combined)
        
        model = Model(inputs=inputs, outputs=outputs)
        
        model.compile(
            optimizer=Adam(learning_rate=self.learning_rate),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def train_neural_network(self, model_name: str, model_builder_func):
        """Train a neural network model"""
        logger.info(f"Training {model_name}...")
        
        # Build model
        model = model_builder_func()
        
        # Calculate class weights
        class_weights = compute_class_weight(
            'balanced', classes=np.unique(self.y_train), y=self.y_train
        )
        class_weight_dict = {i: weight for i, weight in enumerate(class_weights)}
        
        # Callbacks
        callbacks = [
            EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True, verbose=0),
            ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5, min_lr=1e-6, verbose=0)
        ]
        
        # Train model
        start_time = time.time()
        history = model.fit(
            self.X_train, self.y_train,
            batch_size=self.batch_size,
            epochs=self.max_epochs,
            validation_data=(self.X_val, self.y_val),
            callbacks=callbacks,
            class_weight=class_weight_dict,
            verbose=0
        )
        training_time = time.time() - start_time
        
        # Evaluate
        y_pred_proba = model.predict(self.X_test, verbose=0)
        y_pred = np.argmax(y_pred_proba, axis=1)
        
        # Metrics
        accuracy = accuracy_score(self.y_test, y_pred)
        f1_macro = f1_score(self.y_test, y_pred, average='macro')
        f1_weighted = f1_score(self.y_test, y_pred, average='weighted')
        
        # Classification report
        target_names = [self.class_to_name[i] for i in range(len(self.vulnerability_classes))]
        class_report = classification_report(self.y_test, y_pred, target_names=target_names, zero_division=0)
        
        self.results[model_name] = {
            'accuracy': accuracy,
            'f1_macro': f1_macro,
            'f1_weighted': f1_weighted,
            'training_time': training_time,
            'epochs_trained': len(history.history['loss']),
            'classification_report': class_report,
            'model_type': 'Neural Network'
        }
        
        logger.info(f"{model_name} - Accuracy: {accuracy:.4f}, F1-Macro: {f1_macro:.4f}")
        
        return model
    
    def train_random_forest(self):
        """Train Random Forest baseline"""
        logger.info("Training Random Forest...")
        
        # Calculate class weights
        class_weights = compute_class_weight(
            'balanced', classes=np.unique(self.y_train), y=self.y_train
        )
        class_weight_dict = {i: weight for i, weight in enumerate(class_weights)}
        
        # Train Random Forest
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            class_weight=class_weight_dict,
            random_state=42,
            n_jobs=-1
        )
        
        start_time = time.time()
        rf_model.fit(self.X_train_tfidf, self.y_train)
        training_time = time.time() - start_time
        
        # Predictions
        y_pred = rf_model.predict(self.X_test_tfidf)
        
        # Metrics
        accuracy = accuracy_score(self.y_test, y_pred)
        f1_macro = f1_score(self.y_test, y_pred, average='macro')
        f1_weighted = f1_score(self.y_test, y_pred, average='weighted')
        
        # Classification report
        target_names = [self.class_to_name[i] for i in range(len(self.vulnerability_classes))]
        class_report = classification_report(self.y_test, y_pred, target_names=target_names, zero_division=0)
        
        self.results['RandomForest'] = {
            'accuracy': accuracy,
            'f1_macro': f1_macro,
            'f1_weighted': f1_weighted,
            'training_time': training_time,
            'classification_report': class_report,
            'model_type': 'Traditional ML'
        }
        
        logger.info(f"Random Forest - Accuracy: {accuracy:.4f}, F1-Macro: {f1_macro:.4f}")
    
    def load_existing_bilstm_results(self, bilstm_results_path: str):
        """Load existing BiLSTM results"""
        try:
            with open(bilstm_results_path, 'r') as f:
                bilstm_data = json.load(f)
            
            self.results['BiLSTM'] = {
                'accuracy': bilstm_data['test_metrics']['accuracy'],
                'f1_macro': bilstm_data['test_metrics']['f1_score_macro'],
                'f1_weighted': bilstm_data['test_metrics']['f1_score_weighted'],
                'training_time': 0,
                'classification_report': bilstm_data.get('classification_report', ''),
                'model_type': 'Neural Network (Pre-trained)'
            }
            
            logger.info(f"✅ Loaded existing BiLSTM results - Accuracy: {self.results['BiLSTM']['accuracy']:.4f}")
            return True
            
        except Exception as e:
            logger.warning(f"Could not load existing BiLSTM results: {e}")
            return False
    
    def compare_all_architectures(self, existing_bilstm_results_path: str = None):
        """Compare all architectures"""
        logger.info("Starting architecture comparison with your exact data preprocessing...")
        
        # Prepare data once using your exact pipeline
        self.prepare_data()
        
        # Try to load existing BiLSTM results
        if existing_bilstm_results_path and self.load_existing_bilstm_results(existing_bilstm_results_path):
            logger.info("Using existing BiLSTM results")
        else:
            # Train BiLSTM if not loaded
            self.train_neural_network('BiLSTM', self.build_bilstm_model)
        
        # Train other architectures
        self.train_neural_network('CNN', self.build_cnn_model)
        self.train_neural_network('Transformer', self.build_transformer_model)
        self.train_neural_network('Hybrid_CNN_LSTM', self.build_hybrid_cnn_lstm_model)
        self.train_random_forest()
        
        # Generate comparison report
        self.generate_comparison_report()
    
    def generate_comparison_report(self):
        """Generate comprehensive comparison report"""
        logger.info("Generating comparison report...")
        
        # Create results DataFrame
        results_data = []
        for model_name, metrics in self.results.items():
            results_data.append({
                'Model': model_name,
                'Accuracy': metrics['accuracy'],
                'F1-Macro': metrics['f1_macro'],
                'F1-Weighted': metrics['f1_weighted'],
                'Training_Time': metrics['training_time'],
                'Model_Type': metrics['model_type']
            })
        
        df_results = pd.DataFrame(results_data)
        df_results = df_results.sort_values('F1-Macro', ascending=False)
        
        # Print comparison table
        print("\n" + "="*100)
        print("ARCHITECTURE COMPARISON RESULTS")
        print("="*100)
        
        print(f"{'Model':<20} {'Accuracy':<10} {'F1-Macro':<10} {'F1-Weighted':<12} {'Train_Time':<12} {'Type':<15}")
        print("-" * 100)
        
        for _, row in df_results.iterrows():
            print(f"{row['Model']:<20} {row['Accuracy']:<10.4f} {row['F1-Macro']:<10.4f} "
                  f"{row['F1-Weighted']:<12.4f} {row['Training_Time']:<12.1f}s {row['Model_Type']:<15}")
        
        # Best model analysis
        best_model = df_results.iloc[0]
        print(f"\nBEST PERFORMING MODEL: {best_model['Model']}")
        print(f"   F1-Macro Score: {best_model['F1-Macro']:.4f}")
        print(f"   Accuracy: {best_model['Accuracy']:.4f}")
        print(f"   Training Time: {best_model['Training_Time']:.1f}s")
        
        # Performance analysis
        print(f"\nPERFORMANCE ANALYSIS:")
        bilstm_f1 = self.results.get('BiLSTM', {}).get('f1_macro', 0.6074)
        
        for model_name, metrics in self.results.items():
            if model_name != 'BiLSTM':
                improvement = metrics['f1_macro'] - bilstm_f1
                if improvement > 0.01:
                    print(f"   {model_name}: +{improvement:.3f} improvement over BiLSTM")
                elif improvement < -0.01:
                    print(f"   {model_name}: {improvement:.3f} worse than BiLSTM")
                else:
                    print(f"   {model_name}: Similar performance to BiLSTM")
        
        # Architecture insights
        print(f"\nARCHITECTURE INSIGHTS:")
        print("- BiLSTM: Sequential dependency modeling")
        print("- CNN: Local vulnerability pattern detection")
        print("- Transformer: Long-range context understanding")
        print("- Hybrid: Combines pattern + sequence strengths")
        print("- Random Forest: Feature-based traditional ML")
        
        # Save results
        results_path = self.models_output_dir / "architecture_comparison.json"
        with open(results_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        df_results.to_csv(self.models_output_dir / "comparison_summary.csv", index=False)
        
        # Save detailed classification reports
        for model_name, metrics in self.results.items():
            report_path = self.models_output_dir / f"{model_name}_classification_report.txt"
            with open(report_path, 'w') as f:
                f.write(f"Classification Report for {model_name}\n")
                f.write("="*50 + "\n\n")
                f.write(metrics['classification_report'])
        
        logger.info(f"Results and reports saved to {self.models_output_dir}")
        
        return df_results

def main():
    """Main execution"""
    
    # Configuration
    dataset_path = "/Users/ARJUN/java-vulnerability-detection-backup/datasets/complete_wartschinski_final/complete_wartschinski_all_formats.json"
    models_output_dir = "/Users/ARJUN/java-vulnerability-detection-backup/models/architecture_comparison_fixed"
    
    # Path to your existing BiLSTM results
    existing_bilstm_results = "/Users/ARJUN/java-vulnerability-detection-backup/models/java_multiclass_lstm/training_results.json"
    
    # Initialize comparison
    comparator = MultiArchitectureJavaClassifier(dataset_path, models_output_dir)
    
    try:
        # Run comprehensive comparison with your exact data preprocessing
        comparator.compare_all_architectures(existing_bilstm_results)
        
        print("\n" + "="*100)
        print("ARCHITECTURE COMPARISON COMPLETE")
        print("="*100)
        print(f"Results saved to: {models_output_dir}")
        print("\nKey Insights:")
        print("- All models use IDENTICAL data preprocessing as your working BiLSTM")
        print("- BiLSTM: Your proven 60.8% accuracy baseline")  
        print("- CNN: Pattern detection for vulnerability signatures")
        print("- Transformer: Self-attention for complex dependencies")
        print("- Hybrid: Combined CNN pattern + LSTM sequence modeling")
        print("- Random Forest: Traditional ML baseline with TF-IDF features")
        
        print("\nNext Steps:")
        print("1. Check which architecture performs best")
        print("2. Consider ensemble methods with top 2-3 models")
        print("3. Fine-tune hyperparameters of best performing model")
        print("4. Deploy best model for real-world testing")
        
    except Exception as e:
        logger.error(f"Comparison failed: {e}")
        raise

if __name__ == "__main__":
    main()