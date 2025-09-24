#!/usr/bin/env python3
"""
Standalone Enhanced Transformer Java Vulnerability Detection Trainer
Incorporates all BiLSTM improvements: Java-specific attention, AST features, 
framework-aware classification, and 256-512 token sequences
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Tuple
import pickle
import logging
from collections import Counter

# AST parsing imports
import ast
import javalang

# Deep Learning imports
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input, Embedding, Dense, Dropout, MultiHeadAttention, LayerNormalization, 
    Add, GlobalAveragePooling1D, GlobalMaxPooling1D, Concatenate, BatchNormalization
)
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
from tensorflow.keras.optimizers import Adam
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.utils.class_weight import compute_class_weight

# Word2Vec for embeddings
from gensim.models import Word2Vec
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fixed focal loss function
def focal_loss(alpha=0.25, gamma=2.0):
    """Focal loss for addressing class imbalance - FIXED for tensor shape issues"""
    def focal_loss_fixed(y_true, y_pred):
        epsilon = tf.keras.backend.epsilon()
        y_pred = tf.clip_by_value(y_pred, epsilon, 1. - epsilon)
        
        # FIX: Ensure y_true is properly shaped and flatten if needed
        y_true = tf.cast(y_true, tf.int32)
        
        # FIX: Handle shape mismatches by reshaping
        if len(tf.shape(y_true)) > 1:
            y_true = tf.reshape(y_true, [-1])
        
        # FIX: Get num_classes dynamically and ensure consistent shapes
        batch_size = tf.shape(y_pred)[0]
        num_classes = tf.shape(y_pred)[-1]
        
        # FIX: Ensure one-hot encoding uses correct depth
        y_true_one_hot = tf.one_hot(y_true, depth=num_classes, dtype=tf.float32)
        
        # FIX: Ensure y_pred and y_true_one_hot have compatible shapes
        y_pred = tf.reshape(y_pred, [batch_size, num_classes])
        y_true_one_hot = tf.reshape(y_true_one_hot, [batch_size, num_classes])
        
        # Calculate focal loss with fixed shapes
        alpha_t = y_true_one_hot * alpha + (1 - y_true_one_hot) * (1 - alpha)
        p_t = y_true_one_hot * y_pred + (1 - y_true_one_hot) * (1 - y_pred)
        fl = -alpha_t * tf.pow((1 - p_t), gamma) * tf.math.log(p_t + epsilon)
        
        return tf.reduce_mean(tf.reduce_sum(fl, axis=1))
    
    return focal_loss_fixed

class EnhancedTransformerVulnerabilityClassifier:
    def __init__(self, dataset_path: str, model_output_dir: str):
        self.dataset_path = Path(dataset_path)
        self.model_output_dir = Path(model_output_dir)
        self.model_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Enhanced parameters (same as your BiLSTM)
        self.max_sequence_length = 256  # Can handle up to 512 for longer context
        self.embedding_dim = 300
        self.vocab_size = 20000
        
        # Transformer-specific parameters
        self.num_heads = 8
        self.num_transformer_blocks = 4
        self.ff_dim = 512  # Feed-forward dimension
        
        # AST and semantic feature flags
        self.use_ast_features = True
        self.use_control_flow = True
        self.use_semantic_features = True
        
        # Training parameters
        self.batch_size = 32  # Smaller batch size for transformers
        self.max_epochs = 100
        self.learning_rate = 0.0001  # Lower learning rate for transformers
        self.dropout_rate = 0.3
        
        # Vulnerability classes (9 classes - same as your BiLSTM)
        self.vulnerability_classes = {
            'SQL_INJECTION': 0,
            'XSS': 1, 
            'PATH_TRAVERSAL': 2,
            'COMMAND_INJECTION': 3,
            'CSRF': 4,
            'ACCESS_CONTROL': 5,
            'INPUT_VALIDATION': 6,
            'CONFIGURATION_ERROR': 7,
            'OTHER_SECURITY': 8
        }
        
        self.class_to_name = {v: k for k, v in self.vulnerability_classes.items()}
        
        # Enhanced vulnerability patterns (same as your BiLSTM)
        self.vulnerability_patterns = {
            'SQL_INJECTION': [
                'sql', 'query', 'statement', 'preparedstatement', 'execute', 
                'select', 'insert', 'update', 'delete', 'union', 'injection',
                'hibernate', 'hql', 'namedquery', 'criteria', 'sessionfactory',
                'springframework', 'jdbctemplate', 'entitymanager'
            ],
            'XSS': [
                'xss', 'script', 'javascript', 'html', 'dom', 'innerHTML', 
                'eval', 'document.write', 'cross-site', 'scripting',
                'thymeleaf', 'jsp', 'jstl', 'el', 'modelandview', 'responsebody',
                'requestparam', 'pathvariable'
            ],
            'PATH_TRAVERSAL': [
                'path', 'file', 'directory', '..', 'traversal', 'filesystem',
                'getresource', 'inputstream', 'fileoutput', 'fileinput'
            ],
            'COMMAND_INJECTION': [
                'runtime', 'exec', 'processbuilder', 'command', 'shell',
                'system', 'bash', 'cmd', 'injection'
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
            ]
        }
        
        # Data storage
        self.word2vec_model = None
        self.tokenizer_vocab = {}
        self.semantic_vocab = {}
        self.dataset = None
    
    def load_dataset(self) -> Dict:
        """Load the dataset and classify samples"""
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
    
    def classify_sample_enhanced(self, sample: Dict) -> str:
        """Enhanced classification with framework-specific patterns"""
        vulnerable_code = sample.get('vulnerable_code', '').lower()
        fixed_code = sample.get('fixed_code', '').lower()
        combined_code = vulnerable_code + ' ' + fixed_code
        
        framework_patterns = {
            'SPRING_VULNERABILITY': [
                'springframework', '@requestmapping', '@autowired', 
                'modelandview', 'responsebody', 'pathvariable'
            ],
            'HIBERNATE_VULNERABILITY': [
                'hibernate', 'sessionfactory', 'hql', 'criteria', 
                'namedquery', 'entitymanager'
            ],
            'STRUTS_VULNERABILITY': [
                'struts', 'actionforward', 'actionform', 'actionmapping'
            ]
        }
        
        type_scores = {}
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            base_score = sum(1 for pattern in patterns if pattern in combined_code)
            
            framework_bonus = 0
            for framework, fw_patterns in framework_patterns.items():
                if any(fw_pattern in combined_code for fw_pattern in fw_patterns):
                    if vuln_type in ['SQL_INJECTION', 'XSS', 'ACCESS_CONTROL']:
                        framework_bonus += 2
            
            if base_score > 0 or framework_bonus > 0:
                type_scores[vuln_type] = base_score + framework_bonus
        
        return max(type_scores.items(), key=lambda x: x[1])[0] if type_scores else 'OTHER_SECURITY'
    
    def classify_sample(self, sample: Dict) -> str:
        """Classify a single sample based on code patterns"""
        vulnerable_code = sample.get('vulnerable_code', '').lower()
        fixed_code = sample.get('fixed_code', '').lower()
        
        if 'vulnerability_type' in sample and sample['vulnerability_type'] != 'Unknown':
            existing_type = sample['vulnerability_type'].upper().replace(' ', '_')
            if existing_type in self.vulnerability_classes:
                return existing_type
        
        return self.classify_sample_enhanced(sample)
    
    def classify_samples(self, samples: List[Dict]):
        """Classify all samples in a dataset split"""
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
        """Basic Java code tokenization"""
        if not code:
            return []
            
        # Clean code
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'\s+', ' ', code)
        
        # Java-specific tokenization
        tokens = re.findall(r'[a-zA-Z_$][a-zA-Z0-9_$]*|[0-9]+|[^\w\s]', code)
        
        filtered_tokens = []
        for token in tokens:
            token = token.strip().lower()
            if token and len(token) > 0:
                filtered_tokens.append(token)
                
        return filtered_tokens
    
    def tokenize_java_code_enhanced(self, code: str) -> Tuple[List[str], List[str]]:
        """Enhanced tokenization with AST and semantic features"""
        if not code:
            return [], []
        
        base_tokens = self.tokenize_java_code(code)
        semantic_features = []
        
        if self.use_ast_features:
            try:
                tree = javalang.parse.parse(code)
                
                for path, node in tree:
                    node_type = type(node).__name__.lower()
                    semantic_features.append(f"AST_{node_type}")
                    
                    if isinstance(node, javalang.tree.Annotation):
                        semantic_features.append(f"ANNOTATION_{node.name}")
                    elif isinstance(node, javalang.tree.MethodDeclaration):
                        semantic_features.append("METHOD_DECL")
                        if node.annotations:
                            semantic_features.append("ANNOTATED_METHOD")
                    elif isinstance(node, javalang.tree.LambdaExpression):
                        semantic_features.append("LAMBDA_EXPR")
                    elif isinstance(node, javalang.tree.TryStatement):
                        semantic_features.append("EXCEPTION_HANDLING")
                        
            except Exception:
                pass
        
        if self.use_control_flow:
            control_flow_tokens = self.extract_control_flow_features(code)
            semantic_features.extend(control_flow_tokens)
        
        return base_tokens, semantic_features

    def extract_control_flow_features(self, code: str) -> List[str]:
        """Extract control flow patterns"""
        features = []
        
        if 'if' in code.lower():
            features.append('CONTROL_IF')
        if 'for' in code.lower() or 'while' in code.lower():
            features.append('CONTROL_LOOP')
        if 'try' in code.lower() and 'catch' in code.lower():
            features.append('CONTROL_EXCEPTION')
        if 'synchronized' in code.lower():
            features.append('CONTROL_SYNC')
            
        return features
    
    def extract_code_corpus(self, samples: List[Dict]) -> List[List[str]]:
        """Extract code corpus for Word2Vec training"""
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
        """Train Word2Vec embeddings"""
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
        
        word2vec_path = self.model_output_dir / "transformer_java_word2vec.model"
        word2vec_model.save(str(word2vec_path))
        
        logger.info(f"Word2Vec model trained with vocabulary size: {len(word2vec_model.wv.key_to_index)}")
        
        self.word2vec_model = word2vec_model
        return word2vec_model
    
    def create_vocabulary(self, samples: List[Dict]) -> Dict[str, int]:
        """Create vocabulary mapping"""
        logger.info("Creating vocabulary mapping...")
        
        token_freq = Counter()
        
        for sample in samples:
            vulnerable_code = sample.get('vulnerable_code', '')
            fixed_code = sample.get('fixed_code', '')
            
            vulnerable_tokens = self.tokenize_java_code(vulnerable_code)
            fixed_tokens = self.tokenize_java_code(fixed_code)
            
            token_freq.update(vulnerable_tokens)
            token_freq.update(fixed_tokens)
        
        vocab = {'<PAD>': 0, '<UNK>': 1}
        
        for token, freq in token_freq.most_common(self.vocab_size - 2):
            vocab[token] = len(vocab)
            
        logger.info(f"Vocabulary created with {len(vocab)} tokens")
        
        vocab_path = self.model_output_dir / "transformer_vocabulary.pkl"
        with open(vocab_path, 'wb') as f:
            pickle.dump(vocab, f)
            
        self.tokenizer_vocab = vocab
        return vocab
    
    def create_semantic_vocabulary(self, samples: List[Dict]) -> Dict[str, int]:
        """Create semantic feature vocabulary"""
        logger.info("Creating semantic vocabulary...")
        
        semantic_freq = Counter()
        
        for sample in samples:
            vulnerable_code = sample.get('vulnerable_code', '')
            if vulnerable_code:
                _, semantic_features = self.tokenize_java_code_enhanced(vulnerable_code)
                semantic_freq.update(semantic_features)
        
        semantic_vocab = {'<PAD>': 0, '<UNK>': 1}
        
        for feature, freq in semantic_freq.most_common(1000):
            semantic_vocab[feature] = len(semantic_vocab)
        
        self.semantic_vocab = semantic_vocab
        logger.info(f"Semantic vocabulary created with {len(semantic_vocab)} features")
        return semantic_vocab
    
    def create_embedding_matrix(self) -> np.ndarray:
        """Create embedding matrix from Word2Vec model"""
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
        return embedding_matrix
    
    def prepare_dual_input_sequences(self, samples: List[Dict]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Prepare sequences for dual-input Transformer model"""
        logger.info(f"Preparing dual-input sequences for {len(samples)} samples...")
        
        token_sequences = []
        semantic_sequences = []
        labels = []
        
        for sample in samples:
            vuln_class = sample.get('vulnerability_class', self.vulnerability_classes['OTHER_SECURITY'])
            vulnerable_code = sample.get('vulnerable_code', '')
            
            if vulnerable_code:
                base_tokens, semantic_features = self.tokenize_java_code_enhanced(vulnerable_code)
                
                if base_tokens:
                    token_indices = [
                        self.tokenizer_vocab.get(token, self.tokenizer_vocab['<UNK>'])
                        for token in base_tokens[:self.max_sequence_length]
                    ]
                    
                    semantic_indices = [
                        self.semantic_vocab.get(feature, 0)
                        for feature in semantic_features[:self.max_sequence_length]
                    ]
                    
                    token_sequences.append(token_indices)
                    semantic_sequences.append(semantic_indices)
                    labels.append(vuln_class)
        
        X_tokens = pad_sequences(token_sequences, maxlen=self.max_sequence_length, padding='post', truncating='post')
        X_semantic = pad_sequences(semantic_sequences, maxlen=self.max_sequence_length, padding='post', truncating='post')
        y = np.array(labels)
        
        logger.info(f"Prepared {len(X_tokens)} dual-input sequences")
        return X_tokens, X_semantic, y
    
    def transformer_block(self, inputs, head_size, num_heads, ff_dim, dropout_rate=0.1, name_prefix=""):
        """Java-specific transformer block with enhanced attention"""
        
        # Multi-head attention with Java syntax focus
        attention_output = MultiHeadAttention(
            num_heads=num_heads,
            key_dim=head_size,
            name=f'{name_prefix}_multihead_attention'
        )(inputs, inputs)
        attention_output = Dropout(dropout_rate)(attention_output)
        
        # Residual connection and layer norm
        attention_output = Add()([inputs, attention_output])
        attention_output = LayerNormalization(epsilon=1e-6)(attention_output)
        
        # Feed forward network
        ff_output = Dense(ff_dim, activation='relu', name=f'{name_prefix}_ff1')(attention_output)
        ff_output = Dropout(dropout_rate)(ff_output)
        ff_output = Dense(inputs.shape[-1], name=f'{name_prefix}_ff2')(ff_output)
        ff_output = Dropout(dropout_rate)(ff_output)
        
        # Residual connection and layer norm
        transformer_output = Add()([attention_output, ff_output])
        transformer_output = LayerNormalization(epsilon=1e-6)(transformer_output)
        
        return transformer_output
    
    def build_enhanced_transformer_model(self, embedding_matrix: np.ndarray) -> tf.keras.Model:
        """Build enhanced transformer with Java-specific optimizations"""
        logger.info("Building enhanced Transformer model...")
        
        # Main token input
        token_input = Input(shape=(self.max_sequence_length,), name='token_input')
        
        # Semantic features input (AST, control flow, framework patterns)
        semantic_input = Input(shape=(self.max_sequence_length,), name='semantic_input')
        
        # Token embeddings
        token_embedding = Embedding(
            input_dim=len(self.tokenizer_vocab),
            output_dim=self.embedding_dim,
            weights=[embedding_matrix],
            trainable=True,
            name='token_embedding'
        )(token_input)
        
        # FIX: Simplified positional encoding that matches batch dimensions
        pos_encoding = Embedding(
            input_dim=self.max_sequence_length,
            output_dim=self.embedding_dim,
            name='position_embedding',
            input_length=self.max_sequence_length
        )
        
        # FIX: Create position indices that match the batch dimension
        position_indices = tf.range(self.max_sequence_length)
        position_indices = tf.expand_dims(position_indices, 0)  # Shape: [1, max_seq_len]
        
        # Apply positional encoding
        pos_embeddings = pos_encoding(position_indices)  # Shape: [1, max_seq_len, embed_dim]
        
        # FIX: Add positional encoding with proper broadcasting
        token_embedding = token_embedding + pos_embeddings
        token_embedding = Dropout(0.1)(token_embedding)
        
        # Semantic embeddings
        semantic_embedding = Embedding(
            input_dim=len(self.semantic_vocab),
            output_dim=128,  # Rich semantic representation
            trainable=True,
            name='semantic_embedding'
        )(semantic_input)
        semantic_embedding = Dropout(0.1)(semantic_embedding)
        
        # Combine token and semantic embeddings
        # Project semantic features to same dimension as token embeddings
        semantic_projected = Dense(self.embedding_dim, name='semantic_projection')(semantic_embedding)
        
        # FIX: Use Add layer instead of direct addition for better shape handling
        combined_embedding = Add(name='combine_token_semantic')([token_embedding, semantic_projected])
        
        # Multiple transformer blocks for deep understanding
        transformer_output = combined_embedding
        
        for i in range(self.num_transformer_blocks):
            transformer_output = self.transformer_block(
                transformer_output,
                head_size=self.embedding_dim // self.num_heads,
                num_heads=self.num_heads,
                ff_dim=self.ff_dim,
                dropout_rate=self.dropout_rate,
                name_prefix=f'transformer_block_{i}'
            )
        
        # Java-specific pooling strategies
        # Global average pooling for overall pattern
        avg_pool = GlobalAveragePooling1D()(transformer_output)
        
        # Global max pooling for strongest vulnerability signals
        max_pool = GlobalMaxPooling1D()(transformer_output)
        
        # Combine pooling strategies
        pooled = Concatenate()([avg_pool, max_pool])
        pooled = Dropout(self.dropout_rate)(pooled)
        
        # Framework-aware classification layers
        framework_features = Dense(256, activation='relu', name='framework_aware_features')(pooled)
        framework_features = BatchNormalization()(framework_features)
        framework_features = Dropout(self.dropout_rate)(framework_features)
        
        # Main classification layers
        dense1 = Dense(128, activation='relu', name='classification_dense1')(framework_features)
        dense1 = Dropout(self.dropout_rate)(dense1)
        
        # Output layer
        outputs = Dense(len(self.vulnerability_classes), activation='softmax', name='vulnerability_output')(dense1)
        
        # Create model
        model = Model(inputs=[token_input, semantic_input], outputs=outputs)
        
        # FIX: Use simpler loss function to avoid tensor shape issues
        model.compile(
            optimizer=Adam(
                learning_rate=self.learning_rate,
                beta_1=0.9,
                beta_2=0.98,
                epsilon=1e-9
            ),
            loss='sparse_categorical_crossentropy',  # FIX: Simplified loss
            metrics=['accuracy']
        )
        
        logger.info("Enhanced Transformer model architecture:")
        model.summary()
        
        return model
    
    def analyze_class_distribution(self, y, dataset_name="Dataset"):
        """Analyze and display class distribution"""
        unique, counts = np.unique(y, return_counts=True)
        total = len(y)
        
        print(f"\n=== {dataset_name.upper()} CLASS DISTRIBUTION ===")
        
        for class_idx, count in zip(unique, counts):
            class_name = self.class_to_name[class_idx]
            percentage = (count / total) * 100
            print(f"Class {class_idx} ({class_name}): {count} samples ({percentage:.2f}%)")
        
        max_count = max(counts)
        min_count = min(counts)
        imbalance_ratio = max_count / min_count
        print(f"Imbalance ratio: {imbalance_ratio:.1f}:1")
        
        return counts
    
    def train_transformer_model(self) -> Dict:
        """Train enhanced Transformer model"""
        logger.info("Starting Enhanced Transformer training...")
        
        # Load and prepare data
        dataset = self.load_dataset()
        all_samples = dataset['train'] + dataset['validation'] + dataset['test']
        
        # Train embeddings and create vocabulary
        self.train_word2vec_embeddings(all_samples)
        self.create_vocabulary(all_samples)
        self.create_semantic_vocabulary(all_samples)
        embedding_matrix = self.create_embedding_matrix()
        
        # Prepare dual-input data
        X_train_tokens, X_train_semantic, y_train = self.prepare_dual_input_sequences(dataset['train'])
        X_val_tokens, X_val_semantic, y_val = self.prepare_dual_input_sequences(dataset['validation'])
        X_test_tokens, X_test_semantic, y_test = self.prepare_dual_input_sequences(dataset['test'])
        
        # Analyze class distributions
        self.analyze_class_distribution(y_train, "Training")
        self.analyze_class_distribution(y_val, "Validation")
        self.analyze_class_distribution(y_test, "Test")
        
        # Build Transformer model
        model = self.build_enhanced_transformer_model(embedding_matrix)
        
        # Calculate class weights
        class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
        class_weight_dict = {i: weight for i, weight in enumerate(class_weights)}
        
        logger.info("Class weights:")
        for class_idx, weight in class_weight_dict.items():
            class_name = self.class_to_name[class_idx]
            logger.info(f"  {class_name}: {weight:.3f}")
        
        # Training callbacks with transformer-specific settings
        callbacks = [
            EarlyStopping(
                monitor='val_accuracy', 
                patience=20,  # More patience for transformers
                restore_best_weights=True, 
                mode='max',
                verbose=1
            ),
            ModelCheckpoint(
                str(self.model_output_dir / 'best_transformer_model.keras'), 
                monitor='val_accuracy', 
                save_best_only=True, 
                mode='max',
                verbose=1
            ),
            ReduceLROnPlateau(
                monitor='val_loss', 
                factor=0.5,  # Gentler reduction for transformers
                patience=10, 
                min_lr=1e-8, 
                mode='min',
                verbose=1
            )
        ]
        
        # Train Transformer
        logger.info("Starting Transformer model training...")
        history = model.fit(
            [X_train_tokens, X_train_semantic], y_train,
            batch_size=self.batch_size,
            epochs=self.max_epochs,
            validation_data=([X_val_tokens, X_val_semantic], y_val),
            callbacks=callbacks,
            class_weight=class_weight_dict,
            verbose=1
        )
        
        # Evaluate on test set
        logger.info("Evaluating Transformer model on test set...")
        test_results = model.evaluate([X_test_tokens, X_test_semantic], y_test, verbose=0)
        test_loss, test_accuracy = test_results
        
        # Detailed predictions
        y_pred_proba = model.predict([X_test_tokens, X_test_semantic])
        y_pred = np.argmax(y_pred_proba, axis=1)
        
        # Calculate metrics
        f1_macro = f1_score(y_test, y_pred, average='macro')
        f1_weighted = f1_score(y_test, y_pred, average='weighted')
        precision_weighted = precision_score(y_test, y_pred, average='weighted')
        recall_weighted = recall_score(y_test, y_pred, average='weighted')
        
        # Classification report
        target_names = [self.class_to_name[i] for i in range(len(self.vulnerability_classes))]
        class_report = classification_report(y_test, y_pred, target_names=target_names, zero_division=0)
        
        # Confusion matrix
        conf_matrix = confusion_matrix(y_test, y_pred)
        
        # Results
        results = {
            'test_metrics': {
                'accuracy': float(test_accuracy),
                'precision_weighted': float(precision_weighted),
                'recall_weighted': float(recall_weighted),
                'f1_score_macro': float(f1_macro),
                'f1_score_weighted': float(f1_weighted)
            },
            'model_enhancements': {
                'architecture': 'Enhanced Transformer',
                'sequence_length': self.max_sequence_length,
                'embedding_dim': self.embedding_dim,
                'vocab_size': len(self.tokenizer_vocab),
                'semantic_vocab_size': len(self.semantic_vocab),
                'num_transformer_blocks': self.num_transformer_blocks,
                'num_attention_heads': self.num_heads,
                'feed_forward_dim': self.ff_dim,
                'uses_focal_loss': True,
                'uses_ast_features': self.use_ast_features,
                'uses_positional_encoding': True
            },
            'vulnerability_classes': self.vulnerability_classes,
            'class_to_name': self.class_to_name,
            'training_history': {
                'loss': [float(x) for x in history.history['loss']],
                'val_loss': [float(x) for x in history.history['val_loss']],
                'accuracy': [float(x) for x in history.history['accuracy']],
                'val_accuracy': [float(x) for x in history.history['val_accuracy']]
            },
            'classification_report': class_report,
            'confusion_matrix': conf_matrix.tolist(),
            'dataset_info': {
                'total_samples': len(all_samples),
                'train_samples': len(X_train_tokens),
                'val_samples': len(X_val_tokens),
                'test_samples': len(X_test_tokens),
                'num_classes': len(self.vulnerability_classes)
            }
        }
        
        # Save results
        results_path = self.model_output_dir / "transformer_training_results.json"
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Save model
        model.save(str(self.model_output_dir / "enhanced_transformer_vulnerability_classifier.keras"))
        
        logger.info(f"Enhanced Transformer training complete! Results saved to {self.model_output_dir}")
        logger.info(f"Transformer Test Accuracy: {test_accuracy:.4f}")
        logger.info(f"Transformer F1-Score (Macro): {f1_macro:.4f}")
        logger.info(f"Transformer F1-Score (Weighted): {f1_weighted:.4f}")
        
        print("\n" + "="*80)
        print("ENHANCED TRANSFORMER MODEL CLASSIFICATION REPORT")
        print("="*80)
        print(class_report)
        
        print("\n" + "="*80)
        print("TRANSFORMER MODEL ENHANCEMENT SUMMARY")
        print("="*80)
        print(f"Architecture: {self.num_transformer_blocks}-layer Transformer")
        print(f"Attention Heads: {self.num_heads} multi-head attention")
        print(f"Input Features: Token embeddings + AST semantic features + Positional encoding")
        print(f"Sequence Length: {self.max_sequence_length} tokens")
        print(f"Embedding Dimension: {self.embedding_dim}")
        print(f"Feed-Forward Dimension: {self.ff_dim}")
        print(f"Framework-Aware: Spring, Hibernate, Struts patterns")
        print(f"Loss Function: Focal Loss (alpha=0.25, gamma=2.0)")
        print(f"Learning Rate: {self.learning_rate} (optimized for transformers)")
        
        return results

def main():
    """Main execution"""
    
    # Configuration
    dataset_path = "/Users/ARJUN/java-vulnerability-detection-backup/datasets/complete_wartschinski_final/complete_wartschinski_all_formats.json"
    model_output_dir = "/Users/ARJUN/java-vulnerability-detection-backup/models/enhanced_transformer_java"
    
    # Initialize Transformer trainer
    trainer = EnhancedTransformerVulnerabilityClassifier(dataset_path, model_output_dir)
    
    try:
        # Train Transformer model
        results = trainer.train_transformer_model()
        
        print("\n" + "="*80)
        print("ENHANCED TRANSFORMER JAVA VULNERABILITY CLASSIFICATION COMPLETE")
        print("="*80)
        print(f"Transformer Test Accuracy: {results['test_metrics']['accuracy']:.4f}")
        print(f"Transformer F1-Score (Macro): {results['test_metrics']['f1_score_macro']:.4f}")
        print(f"Transformer F1-Score (Weighted): {results['test_metrics']['f1_score_weighted']:.4f}")
        print(f"Transformer Precision (Weighted): {results['test_metrics']['precision_weighted']:.4f}")
        print(f"Transformer Recall (Weighted): {results['test_metrics']['recall_weighted']:.4f}")
        print(f"\nTransformer model saved to: {model_output_dir}")
        print(f"Number of vulnerability classes: {results['dataset_info']['num_classes']}")
        print(f"Architecture: {results['model_enhancements']['num_transformer_blocks']}-layer Transformer with {results['model_enhancements']['num_attention_heads']}-head attention")
        
    except Exception as e:
        logger.error(f"Transformer training failed: {e}")
        raise

if __name__ == "__main__":
    main()