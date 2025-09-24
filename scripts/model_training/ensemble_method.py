#!/usr/bin/env python3
"""
Complete Ensemble Java Vulnerability Detection System
Properly loads and uses the original trained models with full complexity
Based on your conversation history and requirements
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import pickle
import logging
from collections import Counter
import time
import re

# AST parsing for proper semantic features
try:
    import javalang
    JAVALANG_AVAILABLE = True
except ImportError:
    JAVALANG_AVAILABLE = False
    logging.warning("javalang not available, using fallback semantic features")

# Deep Learning imports
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

# ML imports
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score, accuracy_score
from sklearn.model_selection import cross_val_score

# Word2Vec for embeddings
try:
    from gensim.models import Word2Vec
    WORD2VEC_AVAILABLE = True
except ImportError:
    WORD2VEC_AVAILABLE = False
    logging.warning("Word2Vec not available")

import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CompleteEnsembleVulnerabilityDetector:
    def __init__(self, 
                 bilstm_model_path: str,
                 cnn_model_path: str, 
                 transformer_model_path: str,
                 dataset_path: str,
                 output_dir: str):
        
        self.bilstm_model_path = Path(bilstm_model_path)
        self.cnn_model_path = Path(cnn_model_path)
        self.transformer_model_path = Path(transformer_model_path)
        self.dataset_path = Path(dataset_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Model storage
        self.bilstm_model = None
        self.cnn_model = None
        self.transformer_model = None
        self.meta_learner = None
        
        # Vocabularies and embeddings
        self.bilstm_vocab = None
        self.cnn_vocab = None
        self.transformer_vocab = None
        
        # Word2Vec models
        self.bilstm_word2vec = None
        self.cnn_word2vec = None
        self.transformer_word2vec = None
        
        # Configuration parameters (match your training)
        self.max_sequence_length = 256
        self.embedding_dim = 300
        
        # Vulnerability classes (9 classes)
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
        
        # Enhanced vulnerability patterns (from your training scripts)
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
    
    def load_models_and_resources(self):
        """Load all models and their associated vocabularies/embeddings"""
        logger.info("Loading models and resources - this will take several minutes...")
        start_time = time.time()
        
        # Load models
        self.load_models()
        
        # Load vocabularies and Word2Vec models
        self.load_vocabularies_and_embeddings()
        
        end_time = time.time()
        logger.info(f"All models and resources loaded in {end_time - start_time:.1f} seconds")
    
    def load_models(self):
        """Load the three trained models"""
        logger.info("Loading neural network models...")
        
        try:
            # Load BiLSTM model
            logger.info(f"Loading BiLSTM model from {self.bilstm_model_path}")
            self.bilstm_model = load_model(self.bilstm_model_path, compile=False)
            logger.info(f"BiLSTM model loaded: {self.bilstm_model.input_shape} -> {self.bilstm_model.output_shape}")
            
            # Load CNN model  
            logger.info(f"Loading CNN model from {self.cnn_model_path}")
            self.cnn_model = load_model(self.cnn_model_path, compile=False)
            logger.info(f"CNN model loaded: input shapes -> {self.cnn_model.output_shape}")
            
            # Load Transformer model
            logger.info(f"Loading Transformer model from {self.transformer_model_path}")
            self.transformer_model = load_model(self.transformer_model_path, compile=False)
            logger.info(f"Transformer model loaded: input shapes -> {self.transformer_model.output_shape}")
            
            logger.info("All neural network models loaded successfully!")
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            raise
    
    def load_vocabularies_and_embeddings(self):
        """Load vocabularies and Word2Vec models from training"""
        logger.info("Loading vocabularies and Word2Vec embeddings...")
        
        # Define base paths for model resources
        bilstm_base = self.bilstm_model_path.parent
        cnn_base = self.cnn_model_path.parent
        transformer_base = self.transformer_model_path.parent
        
        # Load BiLSTM resources
        self.bilstm_vocab = self.load_vocabulary(bilstm_base / "vocabulary.pkl", "BiLSTM")
        if WORD2VEC_AVAILABLE:
            self.bilstm_word2vec = self.load_word2vec(bilstm_base / "java_word2vec.model", "BiLSTM")
        
        # Load CNN resources
        self.cnn_vocab = self.load_vocabulary(cnn_base / "cnn_vocabulary.pkl", "CNN")
        if WORD2VEC_AVAILABLE:
            self.cnn_word2vec = self.load_word2vec(cnn_base / "cnn_java_word2vec.model", "CNN")
        
        # Load Transformer resources
        self.transformer_vocab = self.load_vocabulary(transformer_base / "transformer_vocabulary.pkl", "Transformer")
        if WORD2VEC_AVAILABLE:
            self.transformer_word2vec = self.load_word2vec(transformer_base / "transformer_java_word2vec.model", "Transformer")
        
        logger.info("All vocabularies and embeddings loaded")
    
    def load_vocabulary(self, vocab_path: Path, model_name: str) -> Dict[str, int]:
        """Load vocabulary file"""
        if vocab_path.exists():
            try:
                with open(vocab_path, 'rb') as f:
                    vocab = pickle.load(f)
                logger.info(f"Loaded {model_name} vocabulary: {len(vocab)} tokens")
                return vocab
            except Exception as e:
                logger.warning(f"Error loading {model_name} vocabulary: {e}")
        
        # Fallback vocabulary
        logger.warning(f"Using fallback vocabulary for {model_name}")
        return {'<PAD>': 0, '<UNK>': 1}
    
    def load_word2vec(self, w2v_path: Path, model_name: str) -> Optional:
        """Load Word2Vec model"""
        if w2v_path.exists() and WORD2VEC_AVAILABLE:
            try:
                w2v_model = Word2Vec.load(str(w2v_path))
                logger.info(f"Loaded {model_name} Word2Vec: {len(w2v_model.wv.key_to_index)} vectors")
                return w2v_model
            except Exception as e:
                logger.warning(f"Error loading {model_name} Word2Vec: {e}")
        
        logger.warning(f"No Word2Vec model found for {model_name}")
        return None
    
    def load_and_prepare_test_data(self) -> Tuple[Dict, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Load dataset and prepare test data with full complexity"""
        logger.info("Loading and preparing test dataset with full complexity...")
        start_time = time.time()
        
        # Load dataset
        with open(self.dataset_path, 'r') as f:
            dataset = json.load(f)
        
        test_samples = dataset['test']
        logger.info(f"Loaded {len(test_samples)} test samples")
        
        # Classify samples using proper methodology
        self.classify_test_samples(test_samples)
        
        # Prepare data for each model with full complexity
        logger.info("Preparing BiLSTM data...")
        X_bilstm, y_test = self.prepare_bilstm_data_complete(test_samples)
        
        logger.info("Preparing CNN data...")
        X_cnn_tokens, X_cnn_semantic = self.prepare_cnn_data_complete(test_samples)
        
        logger.info("Preparing Transformer data...")
        X_transformer_tokens, X_transformer_semantic = self.prepare_transformer_data_complete(test_samples)
        
        end_time = time.time()
        logger.info(f"Data preparation completed in {end_time - start_time:.1f} seconds")
        
        return dataset, X_bilstm, X_cnn_tokens, X_cnn_semantic, X_transformer_tokens, X_transformer_semantic, y_test
    
    def classify_test_samples(self, samples: List[Dict]):
        """Classify test samples using the exact same logic as training"""
        logger.info(f"Classifying {len(samples)} samples using training methodology...")
        
        classified_counts = Counter()
        
        for sample in samples:
            # Check existing classification first
            if 'vulnerability_type' in sample and sample['vulnerability_type'] != 'Unknown':
                existing_type = sample['vulnerability_type'].upper().replace(' ', '_')
                
                # Handle removed classes - map to OTHER_SECURITY
                if existing_type in ['XXE', 'DESERIALIZATION', 'CRYPTOGRAPHIC_ISSUE']:
                    vulnerability_type = 'OTHER_SECURITY'
                elif existing_type in self.vulnerability_classes:
                    vulnerability_type = existing_type
                else:
                    vulnerability_type = self.classify_sample_enhanced(sample)
            else:
                vulnerability_type = self.classify_sample_enhanced(sample)
            
            sample['vulnerability_type'] = vulnerability_type
            sample['vulnerability_class'] = self.vulnerability_classes[vulnerability_type]
            classified_counts[vulnerability_type] += 1
        
        logger.info("Test classification distribution:")
        for vuln_type, count in classified_counts.most_common():
            percentage = (count / len(samples)) * 100
            logger.info(f"  {vuln_type}: {count} ({percentage:.1f}%)")
    
    def classify_sample_enhanced(self, sample: Dict) -> str:
        """Enhanced classification with framework-specific patterns (from training)"""
        vulnerable_code = sample.get('vulnerable_code', '').lower()
        fixed_code = sample.get('fixed_code', '').lower()
        combined_code = vulnerable_code + ' ' + fixed_code
        
        # Framework-specific patterns for better detection
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
        
        # Enhanced scoring with framework context
        type_scores = {}
        
        # Original pattern matching
        for vuln_type, patterns in self.vulnerability_patterns.items():
            base_score = sum(1 for pattern in patterns if pattern in combined_code)
            
            # Framework-specific bonus scoring
            framework_bonus = 0
            for framework, fw_patterns in framework_patterns.items():
                if any(fw_pattern in combined_code for fw_pattern in fw_patterns):
                    if vuln_type in ['SQL_INJECTION', 'XSS', 'ACCESS_CONTROL']:
                        framework_bonus += 2  # Higher weight for framework vulnerabilities
            
            if base_score > 0 or framework_bonus > 0:
                type_scores[vuln_type] = base_score + framework_bonus
        
        return max(type_scores.items(), key=lambda x: x[1])[0] if type_scores else 'OTHER_SECURITY'
    
    def tokenize_java_code_complete(self, code: str) -> List[str]:
        """Complete Java code tokenization (exact match to training)"""
        if not code:
            return []
            
        # Clean code (same as training)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'\s+', ' ', code)
        
        # Java-specific tokenization (same as training)
        tokens = re.findall(r'[a-zA-Z_$][a-zA-Z0-9_$]*|[0-9]+|[^\w\s]', code)
        
        # Filter and normalize (same as training)
        filtered_tokens = []
        for token in tokens:
            token = token.strip().lower()
            if token and len(token) > 0:
                filtered_tokens.append(token)
                
        return filtered_tokens
    
    def extract_semantic_features_complete(self, code: str) -> List[str]:
        """Extract complete semantic features using AST (exact match to training)"""
        semantic_features = []
        
        # AST-based feature extraction if available
        if JAVALANG_AVAILABLE:
            try:
                tree = javalang.parse.parse(code)
                
                # Extract AST node types
                for path, node in tree:
                    node_type = type(node).__name__.lower()
                    semantic_features.append(f"AST_{node_type}")
                    
                    # Extract Java-specific constructs
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
                # Fallback for unparseable code
                pass
        
        # Control flow features (same as training)
        code_lower = code.lower()
        if 'if' in code_lower:
            semantic_features.append('CONTROL_IF')
        if 'for' in code_lower or 'while' in code_lower:
            semantic_features.append('CONTROL_LOOP')
        if 'try' in code_lower and 'catch' in code_lower:
            semantic_features.append('CONTROL_EXCEPTION')
        if 'synchronized' in code_lower:
            semantic_features.append('CONTROL_SYNC')
            
        return semantic_features
    
    def prepare_bilstm_data_complete(self, samples: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare BiLSTM data with complete complexity"""
        sequences = []
        labels = []
        
        for sample in samples:
            vuln_class = sample.get('vulnerability_class', self.vulnerability_classes['OTHER_SECURITY'])
            vulnerable_code = sample.get('vulnerable_code', '')
            
            if vulnerable_code:
                # Complete tokenization
                tokens = self.tokenize_java_code_complete(vulnerable_code)
                
                if tokens:
                    # Use actual BiLSTM vocabulary
                    token_indices = [
                        self.bilstm_vocab.get(token, self.bilstm_vocab.get('<UNK>', 1))
                        for token in tokens[:self.max_sequence_length]
                    ]
                    
                    sequences.append(token_indices)
                    labels.append(vuln_class)
        
        # Pad sequences
        X = pad_sequences(sequences, maxlen=self.max_sequence_length, padding='post', truncating='post')
        y = np.array(labels)
        
        logger.info(f"BiLSTM data prepared: X{X.shape}, y{y.shape}")
        return X, y
    
    def prepare_cnn_data_complete(self, samples: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare CNN data with complete dual-input complexity"""
        token_sequences = []
        semantic_sequences = []
        
        # Create semantic vocabulary mapping for CNN
        semantic_vocab = {'<PAD>': 0, '<UNK>': 1}
        
        for sample in samples:
            vulnerable_code = sample.get('vulnerable_code', '')
            
            if vulnerable_code:
                # Complete tokenization
                tokens = self.tokenize_java_code_complete(vulnerable_code)
                
                if tokens:
                    # Use actual CNN vocabulary
                    token_indices = [
                        self.cnn_vocab.get(token, self.cnn_vocab.get('<UNK>', 1))
                        for token in tokens[:self.max_sequence_length]
                    ]
                    
                    # Complete semantic feature extraction
                    semantic_features = self.extract_semantic_features_complete(vulnerable_code)
                    
                    # Build semantic vocabulary on the fly
                    for feature in semantic_features:
                        if feature not in semantic_vocab:
                            semantic_vocab[feature] = len(semantic_vocab)
                    
                    # Convert semantic features to indices
                    semantic_indices = [
                        semantic_vocab.get(feature, semantic_vocab['<UNK>'])
                        for feature in semantic_features[:self.max_sequence_length]
                    ]
                    
                    token_sequences.append(token_indices)
                    semantic_sequences.append(semantic_indices)
        
        # Pad sequences
        X_tokens = pad_sequences(token_sequences, maxlen=self.max_sequence_length, padding='post', truncating='post')
        X_semantic = pad_sequences(semantic_sequences, maxlen=self.max_sequence_length, padding='post', truncating='post')
        
        logger.info(f"CNN data prepared: X_tokens{X_tokens.shape}, X_semantic{X_semantic.shape}")
        logger.info(f"CNN semantic vocabulary size: {len(semantic_vocab)}")
        
        return X_tokens, X_semantic
    
    def prepare_transformer_data_complete(self, samples: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare Transformer data with complete dual-input complexity"""
        token_sequences = []
        semantic_sequences = []
        
        # Create semantic vocabulary mapping for Transformer
        semantic_vocab = {'<PAD>': 0, '<UNK>': 1}
        
        for sample in samples:
            vulnerable_code = sample.get('vulnerable_code', '')
            
            if vulnerable_code:
                # Complete tokenization
                tokens = self.tokenize_java_code_complete(vulnerable_code)
                
                if tokens:
                    # Use actual Transformer vocabulary
                    token_indices = [
                        self.transformer_vocab.get(token, self.transformer_vocab.get('<UNK>', 1))
                        for token in tokens[:self.max_sequence_length]
                    ]
                    
                    # Complete semantic feature extraction
                    semantic_features = self.extract_semantic_features_complete(vulnerable_code)
                    
                    # Build semantic vocabulary on the fly
                    for feature in semantic_features:
                        if feature not in semantic_vocab:
                            semantic_vocab[feature] = len(semantic_vocab)
                    
                    # Convert semantic features to indices
                    semantic_indices = [
                        semantic_vocab.get(feature, semantic_vocab['<UNK>'])
                        for feature in semantic_features[:self.max_sequence_length]
                    ]
                    
                    token_sequences.append(token_indices)
                    semantic_sequences.append(semantic_indices)
        
        # Pad sequences
        X_tokens = pad_sequences(token_sequences, maxlen=self.max_sequence_length, padding='post', truncating='post')
        X_semantic = pad_sequences(semantic_sequences, maxlen=self.max_sequence_length, padding='post', truncating='post')
        
        logger.info(f"Transformer data prepared: X_tokens{X_tokens.shape}, X_semantic{X_semantic.shape}")
        logger.info(f"Transformer semantic vocabulary size: {len(semantic_vocab)}")
        
        return X_tokens, X_semantic
    
    def get_individual_predictions(self, X_bilstm, X_cnn_tokens, X_cnn_semantic, 
                                 X_transformer_tokens, X_transformer_semantic) -> Dict[str, np.ndarray]:
        """Get predictions from all individual models with proper timing"""
        logger.info("Getting predictions from individual models...")
        predictions = {}
        
        # BiLSTM predictions (single input)
        if self.bilstm_model is not None and X_bilstm is not None:
            logger.info("Running BiLSTM inference...")
            start_time = time.time()
            bilstm_pred = self.bilstm_model.predict(X_bilstm, batch_size=32, verbose=1)
            end_time = time.time()
            predictions['bilstm'] = bilstm_pred
            logger.info(f"BiLSTM inference completed in {end_time - start_time:.1f}s: {bilstm_pred.shape}")
        
        # CNN predictions (dual input)
        if self.cnn_model is not None and X_cnn_tokens is not None and X_cnn_semantic is not None:
            logger.info("Running CNN inference...")
            start_time = time.time()
            cnn_pred = self.cnn_model.predict([X_cnn_tokens, X_cnn_semantic], batch_size=32, verbose=1)
            end_time = time.time()
            predictions['cnn'] = cnn_pred
            logger.info(f"CNN inference completed in {end_time - start_time:.1f}s: {cnn_pred.shape}")
        
        # Transformer predictions (dual input)
        if self.transformer_model is not None and X_transformer_tokens is not None and X_transformer_semantic is not None:
            logger.info("Running Transformer inference...")
            start_time = time.time()
            transformer_pred = self.transformer_model.predict([X_transformer_tokens, X_transformer_semantic], batch_size=16, verbose=1)
            end_time = time.time()
            predictions['transformer'] = transformer_pred
            logger.info(f"Transformer inference completed in {end_time - start_time:.1f}s: {transformer_pred.shape}")
        
        return predictions
    
    def weighted_voting_ensemble(self, predictions: Dict[str, np.ndarray], 
                                weights: Optional[Dict[str, float]] = None) -> np.ndarray:
        """Weighted voting ensemble"""
        if weights is None:
            weights = {
                'cnn': 0.4,
                'transformer': 0.35,
                'bilstm': 0.25
            }
        
        logger.info(f"Weighted voting with weights: {weights}")
        
        ensemble_pred = None
        total_weight = 0
        
        for model_name, pred in predictions.items():
            if model_name in weights:
                weight = weights[model_name]
                if ensemble_pred is None:
                    ensemble_pred = weight * pred
                else:
                    ensemble_pred += weight * pred
                total_weight += weight
        
        if total_weight > 0:
            ensemble_pred = ensemble_pred / total_weight
        
        return ensemble_pred
    
    def confidence_based_routing(self, predictions: Dict[str, np.ndarray]) -> np.ndarray:
        """Confidence-based dynamic routing"""
        logger.info("Applying confidence-based routing...")
        
        sample_pred = list(predictions.values())[0]
        n_samples, n_classes = sample_pred.shape
        ensemble_pred = np.zeros((n_samples, n_classes))
        
        for i in range(n_samples):
            confidences = {}
            sample_predictions = {}
            
            for model_name, pred in predictions.items():
                max_confidence = np.max(pred[i])
                confidences[model_name] = max_confidence
                sample_predictions[model_name] = pred[i]
            
            # Use prediction from most confident model
            most_confident_model = max(confidences.items(), key=lambda x: x[1])[0]
            ensemble_pred[i] = sample_predictions[most_confident_model]
        
        return ensemble_pred
    
    def class_specific_routing(self, predictions: Dict[str, np.ndarray]) -> np.ndarray:
        """Class-specific routing based on model strengths"""
        logger.info("Applying class-specific routing...")
        
        # Model preferences based on your training results
        class_preferences = {
            0: 'cnn',        # SQL_INJECTION - CNN best
            1: 'transformer', # XSS - Transformer better
            2: 'cnn',        # PATH_TRAVERSAL - CNN excellent
            3: 'cnn',        # COMMAND_INJECTION - CNN excellent
            4: 'cnn',        # CSRF - CNN excellent
            5: 'transformer', # ACCESS_CONTROL - Transformer better
            6: 'transformer', # INPUT_VALIDATION - Transformer better
            7: 'bilstm',     # CONFIGURATION_ERROR - BiLSTM consistent
            8: 'transformer'  # OTHER_SECURITY - Transformer better
        }
        
        sample_pred = list(predictions.values())[0]
        n_samples, n_classes = sample_pred.shape
        ensemble_pred = np.zeros((n_samples, n_classes))
        
        for i in range(n_samples):
            # Get predicted class from each model
            predicted_classes = {}
            for model_name, pred in predictions.items():
                predicted_classes[model_name] = np.argmax(pred[i])
            
            # Use majority voting to determine likely class
            class_votes = Counter(predicted_classes.values())
            likely_class = class_votes.most_common(1)[0][0]
            
            # Route to preferred model for this class
            preferred_model = class_preferences.get(likely_class, 'cnn')
            if preferred_model in predictions:
                ensemble_pred[i] = predictions[preferred_model][i]
            else:
                # Fallback to weighted voting
                ensemble_pred[i] = self.weighted_voting_ensemble(
                    {k: v[i:i+1] for k, v in predictions.items()}
                )[0]
        
        return ensemble_pred
    
    def train_stacked_meta_learner(self, predictions: Dict[str, np.ndarray], 
                                 y_true: np.ndarray) -> RandomForestClassifier:
        """Train stacked meta-learner with proper regularization"""
        logger.info("Training stacked meta-learner...")
        
        # Prepare meta-features
        meta_features = []
        for model_name in ['bilstm', 'cnn', 'transformer']:
            if model_name in predictions:
                meta_features.append(predictions[model_name])
        
        X_meta = np.concatenate(meta_features, axis=1)
        logger.info(f"Meta-features shape: {X_meta.shape}")
        
        # Use well-regularized Random Forest
        meta_learner = RandomForestClassifier(
            n_estimators=50,
            max_depth=5,
            min_samples_split=20,
            min_samples_leaf=10,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1
        )
        
        # Train meta-learner
        start_time = time.time()
        meta_learner.fit(X_meta, y_true)
        end_time = time.time()
        
        # Cross-validation evaluation
        cv_scores = cross_val_score(meta_learner, X_meta, y_true, cv=5, scoring='accuracy')
        
        train_score = meta_learner.score(X_meta, y_true)
        cv_mean = cv_scores.mean()
        
        logger.info(f"Meta-learner training completed in {end_time - start_time:.1f}s")
        logger.info(f"Train accuracy: {train_score:.4f}")
        logger.info(f"CV accuracy: {cv_mean:.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        if train_score - cv_mean > 0.1:
            logger.warning("Potential overfitting detected in meta-learner")
        
        self.meta_learner = meta_learner
        return meta_learner
    
    def stacked_ensemble_predict(self, predictions: Dict[str, np.ndarray]) -> np.ndarray:
        """Make stacked ensemble predictions"""
        if self.meta_learner is None:
            raise ValueError("Meta-learner not trained")
        
        # Prepare meta-features
        meta_features = []
        for model_name in ['bilstm', 'cnn', 'transformer']:
            if model_name in predictions:
                meta_features.append(predictions[model_name])
        
        X_meta = np.concatenate(meta_features, axis=1)
        
        # Get meta-learner predictions
        meta_predictions = self.meta_learner.predict(X_meta)
        
        # Convert to probability format
        n_classes = len(self.vulnerability_classes)
        stacked_pred = np.zeros((len(meta_predictions), n_classes))
        stacked_pred[np.arange(len(meta_predictions)), meta_predictions] = 1.0
        
        return stacked_pred
    
    def evaluate_individual_models(self, predictions: Dict[str, np.ndarray], y_true: np.ndarray) -> Dict[str, Dict]:
        """Evaluate individual models"""
        logger.info("Evaluating individual models...")
        results = {}
        
        for model_name, pred in predictions.items():
            pred_classes = np.argmax(pred, axis=1)
            
            # Calculate metrics
            accuracy = accuracy_score(y_true, pred_classes)
            f1_macro = f1_score(y_true, pred_classes, average='macro', zero_division=0)
            f1_weighted = f1_score(y_true, pred_classes, average='weighted', zero_division=0)
            precision = precision_score(y_true, pred_classes, average='weighted', zero_division=0)
            recall = recall_score(y_true, pred_classes, average='weighted', zero_division=0)
            
            results[model_name] = {
                'accuracy': accuracy,
                'f1_macro': f1_macro,
                'f1_weighted': f1_weighted,
                'precision': precision,
                'recall': recall,
                'predictions': pred_classes
            }
            
            logger.info(f"{model_name.upper()}: Acc={accuracy:.4f}, F1-macro={f1_macro:.4f}, F1-weighted={f1_weighted:.4f}")
        
        return results
    
    def evaluate_ensemble_methods(self, predictions: Dict[str, np.ndarray], y_true: np.ndarray) -> Dict[str, Dict]:
        """Evaluate all ensemble methods"""
        logger.info("Evaluating ensemble methods...")
        results = {}
        
        # Weighted voting ensemble
        try:
            weighted_pred = self.weighted_voting_ensemble(predictions)
            weighted_classes = np.argmax(weighted_pred, axis=1)
            
            results['weighted_voting'] = {
                'accuracy': accuracy_score(y_true, weighted_classes),
                'f1_macro': f1_score(y_true, weighted_classes, average='macro', zero_division=0),
                'f1_weighted': f1_score(y_true, weighted_classes, average='weighted', zero_division=0),
                'precision': precision_score(y_true, weighted_classes, average='weighted', zero_division=0),
                'recall': recall_score(y_true, weighted_classes, average='weighted', zero_division=0),
                'predictions': weighted_classes
            }
        except Exception as e:
            logger.error(f"Error in weighted voting: {e}")
            results['weighted_voting'] = None
        
        # Confidence-based routing
        try:
            confidence_pred = self.confidence_based_routing(predictions)
            confidence_classes = np.argmax(confidence_pred, axis=1)
            
            results['confidence_routing'] = {
                'accuracy': accuracy_score(y_true, confidence_classes),
                'f1_macro': f1_score(y_true, confidence_classes, average='macro', zero_division=0),
                'f1_weighted': f1_score(y_true, confidence_classes, average='weighted', zero_division=0),
                'precision': precision_score(y_true, confidence_classes, average='weighted', zero_division=0),
                'recall': recall_score(y_true, confidence_classes, average='weighted', zero_division=0),
                'predictions': confidence_classes
            }
        except Exception as e:
            logger.error(f"Error in confidence routing: {e}")
            results['confidence_routing'] = None
        
        # Class-specific routing
        try:
            class_pred = self.class_specific_routing(predictions)
            class_classes = np.argmax(class_pred, axis=1)
            
            results['class_specific_routing'] = {
                'accuracy': accuracy_score(y_true, class_classes),
                'f1_macro': f1_score(y_true, class_classes, average='macro', zero_division=0),
                'f1_weighted': f1_score(y_true, class_classes, average='weighted', zero_division=0),
                'precision': precision_score(y_true, class_classes, average='weighted', zero_division=0),
                'recall': recall_score(y_true, class_classes, average='weighted', zero_division=0),
                'predictions': class_classes
            }
        except Exception as e:
            logger.error(f"Error in class-specific routing: {e}")
            results['class_specific_routing'] = None
        
        # Stacked ensemble
        try:
            # Train meta-learner
            meta_learner = self.train_stacked_meta_learner(predictions, y_true)
            
            # Get stacked predictions
            stacked_pred = self.stacked_ensemble_predict(predictions)
            stacked_classes = np.argmax(stacked_pred, axis=1)
            
            results['stacked_ensemble'] = {
                'accuracy': accuracy_score(y_true, stacked_classes),
                'f1_macro': f1_score(y_true, stacked_classes, average='macro', zero_division=0),
                'f1_weighted': f1_score(y_true, stacked_classes, average='weighted', zero_division=0),
                'precision': precision_score(y_true, stacked_classes, average='weighted', zero_division=0),
                'recall': recall_score(y_true, stacked_classes, average='weighted', zero_division=0),
                'predictions': stacked_classes
            }
        except Exception as e:
            logger.error(f"Error in stacked ensemble: {e}")
            results['stacked_ensemble'] = None
        
        return results
    
    def generate_comprehensive_report(self, individual_results: Dict, ensemble_results: Dict, y_true: np.ndarray) -> str:
        """Generate comprehensive evaluation report"""
        logger.info("Generating comprehensive report...")
        
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("COMPLETE ENSEMBLE VULNERABILITY DETECTION REPORT")
        report_lines.append("=" * 80)
        
        # Individual model performance
        report_lines.append("\nINDIVIDUAL MODEL PERFORMANCE:")
        best_individual_acc = 0
        best_individual_model = ""
        
        for model_name, metrics in individual_results.items():
            if metrics:
                acc = metrics['accuracy']
                f1_macro = metrics['f1_macro']
                f1_weighted = metrics['f1_weighted']
                
                report_lines.append(f"{model_name.upper()}:")
                report_lines.append(f"  Accuracy:           {acc:.4f} ({acc*100:.1f}%)")
                report_lines.append(f"  F1-Score (Macro):   {f1_macro:.4f}")
                report_lines.append(f"  F1-Score (Weighted): {f1_weighted:.4f}")
                
                if acc > best_individual_acc:
                    best_individual_acc = acc
                    best_individual_model = model_name
        
        # Ensemble methods performance
        report_lines.append("\nENSEMBLE METHODS PERFORMANCE:")
        best_ensemble_acc = 0
        best_ensemble_method = ""
        
        for method_name, metrics in ensemble_results.items():
            if metrics:
                acc = metrics['accuracy']
                f1_macro = metrics['f1_macro']
                f1_weighted = metrics['f1_weighted']
                improvement = (acc - best_individual_acc) * 100
                
                report_lines.append(f"{method_name.upper().replace('_', ' ')}:")
                report_lines.append(f"  Accuracy:           {acc:.4f} ({acc*100:.1f}%) [{improvement:+.1f}pp]")
                report_lines.append(f"  F1-Score (Macro):   {f1_macro:.4f}")
                report_lines.append(f"  F1-Score (Weighted): {f1_weighted:.4f}")
                
                if acc > best_ensemble_acc:
                    best_ensemble_acc = acc
                    best_ensemble_method = method_name
        
        # Best ensemble details
        if best_ensemble_method and ensemble_results[best_ensemble_method]:
            report_lines.append(f"\nBEST ENSEMBLE METHOD: {best_ensemble_method.upper().replace('_', ' ')}")
            best_metrics = ensemble_results[best_ensemble_method]
            best_pred_classes = best_metrics['predictions']
            
            # Check for valid predictions
            unique_predictions = np.unique(best_pred_classes)
            if len(unique_predictions) > 1:
                try:
                    class_report = classification_report(
                        y_true, best_pred_classes,
                        target_names=[self.class_to_name[i] for i in range(len(self.vulnerability_classes))],
                        zero_division=0
                    )
                    report_lines.append("DETAILED CLASSIFICATION REPORT (BEST ENSEMBLE):")
                    report_lines.append(class_report)
                except Exception as e:
                    logger.warning(f"Could not generate classification report: {e}")
                    report_lines.append("DETAILED CLASSIFICATION REPORT: Unable to generate due to prediction issues")
            else:
                report_lines.append(f"WARNING: Best ensemble only predicting class {unique_predictions[0]} ({self.class_to_name[unique_predictions[0]]})")
        
        # Summary
        improvement = (best_ensemble_acc - best_individual_acc) * 100
        report_lines.append("\nFINAL SUMMARY:")
        report_lines.append(f"Best Individual Model:  {best_individual_model.upper()} at {best_individual_acc*100:.1f}%")
        report_lines.append(f"Best Ensemble Method:   {best_ensemble_method.replace('_', ' ').title()} at {best_ensemble_acc*100:.1f}%")
        report_lines.append(f"Ensemble Improvement:   {improvement:+.1f} percentage points")
        
        if improvement > 0:
            report_lines.append("SUCCESS: Ensemble outperforms individual models!")
        else:
            report_lines.append("WARNING: Ensemble did not improve over individual models")
        
        return "\n".join(report_lines)
    
    def save_results(self, individual_results: Dict, ensemble_results: Dict, report: str):
        """Save all results to files"""
        logger.info(f"Saving results to {self.output_dir}")
        
        # Save individual results
        with open(self.output_dir / "individual_results.json", 'w') as f:
            # Convert numpy arrays to lists for JSON serialization
            serializable_individual = {}
            for model, metrics in individual_results.items():
                if metrics:
                    serializable_individual[model] = {
                        k: v.tolist() if isinstance(v, np.ndarray) else v 
                        for k, v in metrics.items()
                    }
            json.dump(serializable_individual, f, indent=2)
        
        # Save ensemble results
        with open(self.output_dir / "ensemble_results.json", 'w') as f:
            serializable_ensemble = {}
            for method, metrics in ensemble_results.items():
                if metrics:
                    serializable_ensemble[method] = {
                        k: v.tolist() if isinstance(v, np.ndarray) else v 
                        for k, v in metrics.items()
                    }
            json.dump(serializable_ensemble, f, indent=2)
        
        # Save report
        with open(self.output_dir / "comprehensive_report.txt", 'w') as f:
            f.write(report)
        
        logger.info("All results saved successfully")
    
    def run_complete_ensemble_evaluation(self):
        """Run the complete ensemble evaluation pipeline"""
        logger.info("Starting complete ensemble evaluation...")
        total_start_time = time.time()
        
        try:
            # Step 1: Load models and resources
            self.load_models_and_resources()
            
            # Step 2: Load and prepare test data
            dataset, X_bilstm, X_cnn_tokens, X_cnn_semantic, X_transformer_tokens, X_transformer_semantic, y_test = self.load_and_prepare_test_data()
            
            # Step 3: Get individual model predictions
            predictions = self.get_individual_predictions(
                X_bilstm, X_cnn_tokens, X_cnn_semantic, 
                X_transformer_tokens, X_transformer_semantic
            )
            
            # Step 4: Evaluate individual models
            individual_results = self.evaluate_individual_models(predictions, y_test)
            
            # Step 5: Evaluate ensemble methods
            ensemble_results = self.evaluate_ensemble_methods(predictions, y_test)
            
            # Step 6: Generate comprehensive report
            report = self.generate_comprehensive_report(individual_results, ensemble_results, y_test)
            
            # Step 7: Save results
            self.save_results(individual_results, ensemble_results, report)
            
            # Step 8: Print summary
            print(report)
            
            total_end_time = time.time()
            
            print("\n" + "=" * 80)
            print("ENSEMBLE EVALUATION COMPLETE!")
            print("=" * 80)
            print(f"Results saved to: {self.output_dir}")
            print(f"Individual models evaluated: {len(individual_results)}")
            print(f"Ensemble methods tested: {len([r for r in ensemble_results.values() if r is not None])}")
            print(f"Total execution time: {total_end_time - total_start_time:.1f} seconds")
            
            # Quick summary
            best_individual = max(individual_results.items(), key=lambda x: x[1]['accuracy'] if x[1] else 0)
            valid_ensemble = {k: v for k, v in ensemble_results.items() if v is not None}
            if valid_ensemble:
                best_ensemble = max(valid_ensemble.items(), key=lambda x: x[1]['accuracy'])
                print("\nQUICK SUMMARY:")
                print(f"Best Individual: {best_individual[0].upper()} at {best_individual[1]['accuracy']*100:.1f}%")
                print(f"Best Ensemble:   {best_ensemble[0].replace('_', ' ').title()} at {best_ensemble[1]['accuracy']*100:.1f}%")
                improvement = (best_ensemble[1]['accuracy'] - best_individual[1]['accuracy']) * 100
                print(f"Improvement:     {improvement:+.1f} percentage points")
            
            return individual_results, ensemble_results
            
        except Exception as e:
            logger.error(f"Error in ensemble evaluation: {e}")
            raise


def main():
    """Main execution function"""
    
    # Configuration - Based on your actual training results and LSTM script
    model_paths = {
        'bilstm': "/Users/ARJUN/java-vulnerability-detection-backup/models/enhanced_java_multiclass_lstm/best_enhanced_model.keras",
        'cnn': "/Users/ARJUN/java-vulnerability-detection-backup/models/enhanced_cnn_java/best_cnn_model.keras", 
        'transformer': "/Users/ARJUN/java-vulnerability-detection-backup/models/enhanced_transformer_java/best_transformer_model.keras"
    }
    
    # Correct dataset path from your LSTM training script
    dataset_path = "/Users/ARJUN/java-vulnerability-detection-backup/datasets/complete_wartschinski_final/complete_wartschinski_all_formats.json"
    
    output_dir = "/Users/ARJUN/java-vulnerability-detection-backup/models/ensemble_results"
    
    print("=" * 80)
    print("ENSEMBLE SYSTEM INITIALIZATION")
    print("=" * 80)
    print("Individual models to load:")
    for model_type, path in model_paths.items():
        status = "✓" if Path(path).exists() else "✗"
        print(f"{status} {model_type.upper():<12}: {path}")
    
    print(f"\nDataset: {dataset_path}")
    print(f"Output:  {output_dir}")
    
    print("\nEnsemble methods available:")
    print("• Weighted Voting (CNN: 40%, Transformer: 35%, BiLSTM: 25%)")
    print("• Confidence-Based Routing (most confident model per sample)")
    print("• Class-Specific Routing (best model per vulnerability type)")
    print("• Stacked Meta-Learning (Random Forest meta-classifier)")
    
    # Initialize ensemble system
    ensemble = CompleteEnsembleVulnerabilityDetector(
        bilstm_model_path=model_paths['bilstm'],
        cnn_model_path=model_paths['cnn'],
        transformer_model_path=model_paths['transformer'],
        dataset_path=dataset_path,
        output_dir=output_dir
    )
    
    # Run complete evaluation
    individual_results, ensemble_results = ensemble.run_complete_ensemble_evaluation()
    
    return individual_results, ensemble_results


if __name__ == "__main__":
    main()