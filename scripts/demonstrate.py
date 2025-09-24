#!/usr/bin/env python3
"""
Java Vulnerability Detection Demonstration Script
Based on working CNN & BiLSTM demo approach
"""

import sys
import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
import re
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.colors import LinearSegmentedColormap
import seaborn as sns

# TensorFlow for model loading
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Custom layers for Transformer model loading
class PositionalEncoding(tf.keras.layers.Layer):
    def __init__(self, max_seq_len, d_model, **kwargs):
        kwargs.pop('trainable', None)  # Remove problematic argument
        super().__init__(**kwargs)
        self.max_seq_len = max_seq_len
        self.d_model = d_model
        
    def build(self, input_shape):
        # Create positional encoding matrix
        pe = tf.zeros((self.max_seq_len, self.d_model))
        position = tf.cast(tf.range(0, self.max_seq_len)[:, tf.newaxis], tf.float32)
        
        # Create div_term for all dimensions
        div_term = tf.exp(tf.cast(tf.range(0, self.d_model, 2), tf.float32) * 
                         -(tf.math.log(10000.0) / tf.cast(self.d_model, tf.float32)))
        
        # Apply sin to even indices
        pe_sin = tf.sin(position * div_term)
        # Apply cos to odd indices
        pe_cos = tf.cos(position * div_term)
        
        # Interleave sin and cos
        pe_list = []
        for i in range(self.d_model // 2):
            pe_list.append(pe_sin[:, i:i+1])
            pe_list.append(pe_cos[:, i:i+1])
        
        # Handle odd d_model
        if self.d_model % 2 == 1:
            pe_list.append(pe_sin[:, -1:])
            
        pe = tf.concat(pe_list, axis=1)
        
        # Store as non-trainable weight
        self.pe = self.add_weight(
            name='positional_encoding',
            shape=(self.max_seq_len, self.d_model),
            initializer='zeros',
            trainable=False
        )
        self.pe.assign(pe)
        
        super().build(input_shape)
        
    def call(self, inputs):
        seq_len = tf.shape(inputs)[1]
        # Add positional encoding to inputs
        return inputs + self.pe[:seq_len, :]
    
    def get_config(self):
        config = super().get_config()
        config.update({
            'max_seq_len': self.max_seq_len,
            'd_model': self.d_model
        })
        return config

class TransformerBlock(tf.keras.layers.Layer):
    def __init__(self, d_model, num_heads, ff_dim, dropout_rate=0.1, **kwargs):
        kwargs.pop('trainable', None)  # Remove problematic argument
        super().__init__(**kwargs)
        self.d_model = d_model
        self.num_heads = num_heads
        self.ff_dim = ff_dim
        self.dropout_rate = dropout_rate
        
    def build(self, input_shape):
        self.att = tf.keras.layers.MultiHeadAttention(
            num_heads=self.num_heads, key_dim=self.d_model
        )
        self.ffn = tf.keras.Sequential([
            tf.keras.layers.Dense(self.ff_dim, activation="relu"),
            tf.keras.layers.Dense(self.d_model),
        ])
        self.layernorm1 = tf.keras.layers.LayerNormalization(epsilon=1e-6)
        self.layernorm2 = tf.keras.layers.LayerNormalization(epsilon=1e-6)
        self.dropout1 = tf.keras.layers.Dropout(self.dropout_rate)
        self.dropout2 = tf.keras.layers.Dropout(self.dropout_rate)
        super().build(input_shape)
        
    def call(self, inputs, training=False):
        attn_output = self.att(inputs, inputs)
        attn_output = self.dropout1(attn_output, training=training)
        out1 = self.layernorm1(inputs + attn_output)
        ffn_output = self.ffn(out1)
        ffn_output = self.dropout2(ffn_output, training=training)
        return self.layernorm2(out1 + ffn_output)
    
    def get_config(self):
        config = super().get_config()
        config.update({
            'd_model': self.d_model,
            'num_heads': self.num_heads,
            'ff_dim': self.ff_dim,
            'dropout_rate': self.dropout_rate
        })
        return config

class JavaVulnDemo:
    def __init__(self):
        self.base_path = Path(".")
        self.models_path = self.base_path / "models"
        self.results_path = self.base_path / "results"
        self.demo_path = self.results_path / "demonstration"
        self.demo_path.mkdir(parents=True, exist_ok=True)
        
        # Available models
        self.available_models = {
            'cnn': {
                'model_file': 'cnn_vulnerability_model.h5',
                'tokenizer_file': 'cnn_tokenizer.pkl',
                'sequence_length': 256,
                'color': 'red',
                'name': 'CNN'
            },
            'bilstm': {
                'model_file': 'bilstm_best_model.h5',
                'tokenizer_file': 'bilstm_tokenizer.json',
                'sequence_length': 512,
                'color': 'blue',
                'name': 'BiLSTM'
            },
            'transformer': {
                'model_file': 'transformer_best_model.keras',
                'tokenizer_file': 'transformer_tokenizer.pkl',
                'sequence_length': 256,
                'color': 'green',
                'name': 'Transformer'
            }
        }
        
        # Sample vulnerable Java code snippets
        self.sample_codes = {
            'sql_injection': '''public class UserLogin {
    public boolean authenticateUser(String username, String password) {
        Connection conn = getConnection();
        // VULNERABLE: Direct string concatenation allows SQL injection
        String query = "SELECT * FROM users WHERE username='" + username + 
                      "' AND password='" + password + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return rs.next();
    }
}''',
            
            'xss_vulnerability': '''public class CommentController {
    @RequestMapping("/comment")
    public String displayComment(@RequestParam String userComment, Model model) {
        // VULNERABLE: No output encoding allows XSS attacks
        model.addAttribute("comment", userComment);
        return "comment_page"; // Renders: <div>${comment}</div>
    }
    
    @RequestMapping("/search")
    public void searchResults(HttpServletResponse response, String query) throws IOException {
        // VULNERABLE: Direct output without encoding
        response.getWriter().println("Search results for: " + query);
    }
}''',
            
            'command_injection': '''public class FileProcessor {
    public void processFile(String filename, String format) throws IOException {
        // VULNERABLE: User input directly in command execution
        String command = "convert " + filename + " output." + format;
        Runtime.getRuntime().exec(command);
    }
    
    public void backupFile(String filepath) throws IOException {
        // VULNERABLE: Shell command injection
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "cp " + filepath + " /backup/");
        pb.start();
    }
}''',
            
            'path_traversal': '''public class FileHandler {
    public String readUserFile(String fileName) throws IOException {
        // VULNERABLE: No path validation allows directory traversal
        String filePath = "/app/user_files/" + fileName;
        return Files.readString(Paths.get(filePath));
    }
    
    public void downloadFile(String filename, HttpServletResponse response) throws IOException {
        // VULNERABLE: Path traversal in file download
        File file = new File("uploads/" + filename);
        Files.copy(file.toPath(), response.getOutputStream());
    }
}''',
            
            'deserialization': '''public class DataProcessor {
    public Object loadUserData(InputStream input) throws IOException, ClassNotFoundException {
        // VULNERABLE: Unsafe deserialization
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();  // Can execute arbitrary code
    }
    
    public User parseUserFromXML(String xmlData) throws Exception {
        // VULNERABLE: XML external entity (XXE)
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return parseUser(builder.parse(new ByteArrayInputStream(xmlData.getBytes())));
    }
}''',
            
            'secure_example': '''public class SecureUserLogin {
    public boolean authenticateUser(String username, String password) {
        Connection conn = getConnection();
        // SECURE: Using prepared statements prevents SQL injection
        String query = "SELECT * FROM users WHERE username=? AND password=?";
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, username);
            pstmt.setString(2, hashPassword(password)); // Hash passwords
            ResultSet rs = pstmt.executeQuery();
            return rs.next();
        }
    }
    
    private String hashPassword(String password) {
        // Proper password hashing
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }
}'''
        }

    def load_model_and_tokenizer(self, model_type):
        """Load a specific model and its tokenizer"""
        logger.info(f"Loading {model_type} model...")
        
        if model_type not in self.available_models:
            raise ValueError(f"Model type {model_type} not available. Choose from: {list(self.available_models.keys())}")
        
        model_info = self.available_models[model_type]
        
        # Load model
        model_path = self.models_path / model_info['model_file']
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        # Load model with custom objects for specific models
        if model_type == 'bilstm':
            def f1_loss(y_true, y_pred):
                def recall(y_true, y_pred):
                    true_positives = tf.keras.backend.sum(tf.keras.backend.round(tf.keras.backend.clip(y_true * y_pred, 0, 1)))
                    possible_positives = tf.keras.backend.sum(tf.keras.backend.round(tf.keras.backend.clip(y_true, 0, 1)))
                    recall = true_positives / (possible_positives + tf.keras.backend.epsilon())
                    return recall

                def precision(y_true, y_pred):
                    true_positives = tf.keras.backend.sum(tf.keras.backend.round(tf.keras.backend.clip(y_true * y_pred, 0, 1)))
                    predicted_positives = tf.keras.backend.sum(tf.keras.backend.round(tf.keras.backend.clip(y_pred, 0, 1)))
                    precision = true_positives / (predicted_positives + tf.keras.backend.epsilon())
                    return precision

                precision_val = precision(y_true, y_pred)
                recall_val = recall(y_true, y_pred)
                return 1 - 2*((precision_val*recall_val)/(precision_val+recall_val+tf.keras.backend.epsilon()))

            def f1_metric(y_true, y_pred):
                def recall(y_true, y_pred):
                    true_positives = tf.keras.backend.sum(tf.keras.backend.round(tf.keras.backend.clip(y_true * y_pred, 0, 1)))
                    possible_positives = tf.keras.backend.sum(tf.keras.backend.round(tf.keras.backend.clip(y_true, 0, 1)))
                    recall = true_positives / (possible_positives + tf.keras.backend.epsilon())
                    return recall

                def precision(y_true, y_pred):
                    true_positives = tf.keras.backend.sum(tf.keras.backend.round(tf.keras.backend.clip(y_true * y_pred, 0, 1)))
                    predicted_positives = tf.keras.backend.sum(tf.keras.backend.round(tf.keras.backend.clip(y_pred, 0, 1)))
                    precision = true_positives / (predicted_positives + tf.keras.backend.epsilon())
                    return precision

                precision_val = precision(y_true, y_pred)
                recall_val = recall(y_true, y_pred)
                return 2*((precision_val*recall_val)/(precision_val+recall_val+tf.keras.backend.epsilon()))
            
            custom_objects = {
                'f1_loss': f1_loss,
                'f1': f1_metric,
                'f1_metric': f1_metric
            }
            
            model = load_model(str(model_path), custom_objects=custom_objects, compile=False)
        elif model_type == 'transformer':
            custom_objects = {
                'PositionalEncoding': PositionalEncoding,
                'TransformerBlock': TransformerBlock
            }
            
            model = load_model(str(model_path), custom_objects=custom_objects, compile=False)
        else:
            model = load_model(str(model_path))
        
        # Load tokenizer
        tokenizer_path = self.models_path / model_info['tokenizer_file']
        if not tokenizer_path.exists():
            raise FileNotFoundError(f"Tokenizer file not found: {tokenizer_path}")
        
        if tokenizer_path.suffix == '.pkl':
            with open(tokenizer_path, 'rb') as f:
                tokenizer = pickle.load(f)
        else:  # JSON format for BiLSTM
            with open(tokenizer_path, 'r') as f:
                tokenizer_json = f.read()
            tokenizer = tokenizer_from_json(tokenizer_json)
        
        logger.info(f"Successfully loaded {model_type} model and tokenizer")
        
        return model, tokenizer, model_info

    def preprocess_code_for_model(self, code, model_type):
        """Preprocess code based on model type"""
        if model_type == 'cnn':
            return self.preprocess_for_cnn(code)
        elif model_type == 'bilstm':
            return self.preprocess_for_bilstm(code)
        else:
            return code.lower()

    def preprocess_for_cnn(self, code):
        """CNN-specific preprocessing (pattern-focused)"""
        processed = code.lower()
        
        # Normalize vulnerability patterns for CNN pattern detection
        processed = re.sub(r'select\s+.*?\s+from', 'SQL_SELECT_PATTERN', processed)
        processed = re.sub(r'insert\s+into', 'INSERT_PATTERN', processed)
        processed = re.sub(r'update\s+.*?\s+set', 'UPDATE_PATTERN', processed)
        processed = re.sub(r'runtime\.exec', 'RUNTIME_EXEC_PATTERN', processed)
        processed = re.sub(r'processbuilder', 'PROCESS_BUILDER_PATTERN', processed)
        processed = re.sub(r'<script.*?>', 'SCRIPT_TAG_PATTERN', processed)
        processed = re.sub(r'document\.write', 'DOCUMENT_WRITE_PATTERN', processed)
        processed = re.sub(r'\.\./', 'PATH_TRAVERSAL_PATTERN', processed)
        processed = re.sub(r'objectinputstream', 'OBJECT_INPUT_STREAM_PATTERN', processed)
        
        return ' '.join(processed.split())

    def preprocess_for_bilstm(self, code):
        """BiLSTM-specific preprocessing (sequence-focused)"""
        processed = code.lower()
        # Basic preprocessing for BiLSTM - preserve sequence structure
        processed = re.sub(r'\s+', ' ', processed.strip())
        processed = re.sub(r'([{}();,.])', r' \1 ', processed)
        return ' '.join(processed.split())

    def get_vulnerability_predictions_sliding_window(self, code, model, tokenizer, model_info, step_size=5):
        """Get vulnerability predictions using sliding window approach like Laura's method"""
        sequence_length = model_info['sequence_length']
        
        # Preprocess code
        processed_code = self.preprocess_code_for_model(code, model_info.get('name', '').lower())
        
        # Tokenize
        sequences = tokenizer.texts_to_sequences([processed_code])
        if not sequences or not sequences[0]:
            return []
        
        tokens = sequences[0]
        
        # Define multiple thresholds like Laura's approach
        thresholds = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1]
        
        predictions = []
        
        # Sliding window over the source code
        focus = 0
        last_focus = 0
        
        while focus < len(code):
            # Get context window around current position
            context_start = max(0, focus - sequence_length // 2)
            context_end = min(len(code), focus + sequence_length // 2)
            
            # Extract context text
            context_text = code[context_start:context_end]
            context_processed = self.preprocess_code_for_model(context_text, model_info.get('name', '').lower())
            
            # Tokenize context
            context_sequences = tokenizer.texts_to_sequences([context_processed])
            
            if context_sequences and context_sequences[0]:
                # Pad sequence
                padded_context = pad_sequences(context_sequences, maxlen=sequence_length, padding='post')
                
                try:
                    # Predict vulnerability
                    if len(model.inputs) > 1:
                        # Try with dummy features for hybrid models
                        prediction = model.predict([padded_context, np.zeros((1, 15))], verbose=0)
                    else:
                        prediction = model.predict(padded_context, verbose=0)
                    
                    score = float(prediction[0][0]) if hasattr(prediction, 'shape') and len(prediction.shape) > 1 else float(prediction[0])
                    
                    # Store prediction with position
                    predictions.append({
                        'start': focus,
                        'end': min(focus + step_size, len(code)),
                        'score': score,
                        'context_start': context_start,
                        'context_end': context_end
                    })
                    
                except Exception as e:
                    logger.debug(f"Prediction failed at position {focus}: {e}")
                    predictions.append({
                        'start': focus,
                        'end': min(focus + step_size, len(code)),
                        'score': 0.0,
                        'context_start': context_start,
                        'context_end': context_end
                    })
            
            # Move to next position
            last_focus = focus
            # Find next natural break point (space, newline, operator)
            next_break = self.find_next_break(code, focus + step_size)
            if next_break > focus:
                focus = next_break
            else:
                focus += step_size
                
            if focus >= len(code):
                break
        
        return predictions

    def find_next_break(self, code, start_pos):
        """Find next natural break point in code (space, newline, operator)"""
        if start_pos >= len(code):
            return len(code)
            
        # Look for natural break points
        break_chars = [' ', '\n', '\t', ';', '{', '}', '(', ')', '+', '-', '*', '/', '=']
        
        for i in range(start_pos, min(start_pos + 10, len(code))):
            if code[i] in break_chars:
                return i + 1
                
        return start_pos

    def get_color_for_score(self, score, thresholds):
        """Get color based on vulnerability score using Laura's color scheme"""
        if score > thresholds[0]:    # > 0.9
            return "darkred", "#8B0000"
        elif score > thresholds[1]:  # > 0.8
            return "red", "#FF0000"
        elif score > thresholds[2]:  # > 0.7
            return "darkorange", "#FF8C00"
        elif score > thresholds[3]:  # > 0.6
            return "orange", "#FFA500"
        elif score > thresholds[4]:  # > 0.5
            return "gold", "#FFD700"
        elif score > thresholds[5]:  # > 0.4
            return "yellow", "#FFFF00"
        elif score > thresholds[6]:  # > 0.3
            return "greenyellow", "#ADFF2F"
        elif score > thresholds[7]:  # > 0.2
            return "limegreen", "#32CD32"
        elif score > thresholds[8]:  # > 0.1
            return "green", "#008000"
        else:
            return "darkgreen", "#006400"

    def create_vulnerability_heatmap_sliding(self, code, predictions, model_type, threshold=0.5):
        """Create vulnerability heatmap using sliding window approach like Laura's method"""
        
        # Define thresholds
        thresholds = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1]
        
        # Create character-level vulnerability mapping
        char_scores = [0.0] * len(code)
        char_colors = ['#F5F5F5'] * len(code)  # Default light gray
        
        # Apply predictions to character positions
        for pred in predictions:
            start_pos = pred['start']
            end_pos = pred['end']
            score = pred['score']
            
            # Get color for this score
            color_name, color_hex = self.get_color_for_score(score, thresholds)
            
            # Apply to character range
            for i in range(start_pos, min(end_pos, len(code))):
                if score > char_scores[i]:  # Use highest score for overlapping regions
                    char_scores[i] = score
                    char_colors[i] = color_hex
        
        # Split into lines for visualization
        lines = code.split('\n')
        line_start_positions = []
        pos = 0
        for line in lines:
            line_start_positions.append(pos)
            pos += len(line) + 1  # +1 for newline
        
        # Create visualization
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(20, max(12, len(lines) * 0.5)))
        
        # Left panel: Code with character-level coloring
        ax1.set_xlim(0, 1)
        ax1.set_ylim(0, len(lines))
        
        vulnerable_lines = []
        
        for line_idx, line in enumerate(lines):
            line_start = line_start_positions[line_idx]
            line_end = line_start + len(line)
            
            y_pos = len(lines) - line_idx - 1
            
            # Get scores for this line
            line_scores = char_scores[line_start:line_end] if line_end <= len(char_scores) else char_scores[line_start:]
            line_colors = char_colors[line_start:line_end] if line_end <= len(char_colors) else char_colors[line_start:]
            
            max_line_score = max(line_scores) if line_scores else 0.0
            
            # Only highlight lines with significant vulnerability scores
            if max_line_score > threshold:
                vulnerable_lines.append({
                    'line_number': line_idx + 1,
                    'content': line,
                    'score': max_line_score,
                    'colors': line_colors
                })
                
                # Draw background with dominant color
                dominant_color = max(set(line_colors), key=line_colors.count) if line_colors else '#F5F5F5'
                
                # Create rectangle for the line
                from matplotlib.patches import Rectangle
                rect = Rectangle((0, y_pos), 1, 0.9, 
                               facecolor=dominant_color, alpha=0.7, 
                               edgecolor='black', linewidth=1)
                ax1.add_patch(rect)
                
                # Add line number
                ax1.text(0.02, y_pos + 0.45, f"{line_idx + 1:3d}", 
                        fontsize=10, va='center', ha='left', weight='bold',
                        color='white' if max_line_score > 0.6 else 'black')
                
                # Add code text
                display_line = line[:75] + "..." if len(line) > 75 else line
                ax1.text(0.08, y_pos + 0.45, display_line, 
                        fontsize=9, va='center', ha='left', fontfamily='monospace',
                        color='white' if max_line_score > 0.6 else 'black',
                        weight='bold')
                
                # Add vulnerability score
                ax1.text(0.95, y_pos + 0.45, f"{max_line_score:.3f}", 
                        fontsize=10, va='center', ha='right', weight='bold',
                        bbox=dict(boxstyle="round,pad=0.3", 
                                 facecolor='red' if max_line_score > 0.8 else 'orange',
                                 alpha=0.8),
                        color='white')
            else:
                # Non-vulnerable line - minimal styling
                ax1.text(0.02, y_pos + 0.45, f"{line_idx + 1:3d}", 
                        fontsize=9, va='center', ha='left', color='gray')
                
                display_line = line[:75] + "..." if len(line) > 75 else line
                ax1.text(0.08, y_pos + 0.45, display_line, 
                        fontsize=8, va='center', ha='left', fontfamily='monospace',
                        color='gray', alpha=0.6)
        
        ax1.set_title(f'{model_type.upper()} Vulnerability Analysis\n'
                     f'Sliding Window Method - {len(vulnerable_lines)} vulnerable lines detected', 
                     fontsize=14, weight='bold')
        ax1.set_xlabel('Java Source Code with Vulnerability Highlighting', fontsize=12)
        ax1.set_xticks([])
        ax1.set_yticks([])
        
        # Add color legend
        legend_elements = []
        colors_used = ['darkred', 'red', 'darkorange', 'orange', 'gold', 'yellow', 'greenyellow', 'limegreen', 'green', 'darkgreen']
        thresholds_labels = ['> 0.9', '> 0.8', '> 0.7', '> 0.6', '> 0.5', '> 0.4', '> 0.3', '> 0.2', '> 0.1', '≤ 0.1']
        
        for color, label in zip(colors_used, thresholds_labels):
            legend_elements.append(plt.Rectangle((0,0),1,1, facecolor=color, alpha=0.7, label=label))
        
        ax1.legend(handles=legend_elements[:5], loc='upper right', title='Vulnerability Score', fontsize=8)
        
        # Right panel: Vulnerable lines analysis
        if vulnerable_lines:
            # Sort by score descending
            vulnerable_lines_sorted = sorted(vulnerable_lines, key=lambda x: x['score'], reverse=True)
            
            scores = [v['score'] for v in vulnerable_lines_sorted]
            line_numbers = [v['line_number'] for v in vulnerable_lines_sorted]
            colors = [self.get_color_for_score(score, thresholds)[1] for score in scores]
            
            y_positions = range(len(vulnerable_lines_sorted))
            
            bars = ax2.barh(y_positions, scores, color=colors, alpha=0.8, edgecolor='black')
            
            # Add threshold lines
            for i, thresh in enumerate(thresholds[:5]):  # Show first 5 thresholds
                ax2.axvline(x=thresh, color='red', linestyle='--', alpha=0.5, linewidth=1)
                ax2.text(thresh, len(vulnerable_lines_sorted) * (0.9 - i*0.1), f'{thresh}', 
                        fontsize=8, ha='center', va='bottom')
            
            ax2.set_yticks(y_positions)
            ax2.set_yticklabels([f'Line {ln}' for ln in line_numbers])
            ax2.set_xlabel('Vulnerability Score', fontsize=12)
            ax2.set_title(f'Top Vulnerable Lines\n(Threshold: {threshold})', fontsize=12, weight='bold')
            ax2.set_xlim(0, 1)
            ax2.grid(True, alpha=0.3)
            
            # Add score annotations
            for i, (score, line_num) in enumerate(zip(scores, line_numbers)):
                ax2.text(score + 0.02, i, f'{score:.3f}', 
                        va='center', ha='left', fontsize=9, weight='bold')
            
            # Add vulnerability summary
            critical_count = sum(1 for s in scores if s > 0.8)
            high_count = sum(1 for s in scores if 0.6 < s <= 0.8)
            medium_count = sum(1 for s in scores if 0.4 < s <= 0.6)
            
            summary_text = f"Vulnerability Summary:\n"
            summary_text += f"Critical (>0.8): {critical_count}\n"
            summary_text += f"High (0.6-0.8): {high_count}\n"
            summary_text += f"Medium (0.4-0.6): {medium_count}\n"
            summary_text += f"Total vulnerable: {len(vulnerable_lines)}"
            
            ax2.text(0.02, 0.98, summary_text, transform=ax2.transAxes, 
                    fontsize=10, va='top', ha='left',
                    bbox=dict(boxstyle="round,pad=0.5", facecolor='lightgray', alpha=0.8))
        else:
            ax2.text(0.5, 0.5, 'No vulnerabilities detected\nabove threshold', 
                    transform=ax2.transAxes, ha='center', va='center', 
                    fontsize=16, weight='bold', color='green')
            ax2.set_xticks([])
            ax2.set_yticks([])
        
        plt.tight_layout()
        return fig, vulnerable_lines

    def create_vulnerability_heatmap(self, code, predictions, model_type, model_color, threshold=0.5):
        """Create a heatmap visualization of vulnerability predictions"""
        
        lines = code.split('\n')
        line_predictions = []
        
        # Calculate predictions per line
        current_pos = 0
        for line_idx, line in enumerate(lines):
            line_start = current_pos
            line_end = current_pos + len(line)
            
            # Find predictions that overlap with this line
            line_scores = []
            for start, end, score in predictions:
                if start <= line_end and end >= line_start:
                    line_scores.append(score)
            
            avg_score = np.mean(line_scores) if line_scores else 0.0
            line_predictions.append(avg_score)
            current_pos = line_end + 1  # +1 for newline character
        
        # Create visualization
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(20, max(10, len(lines) * 0.4)))
        
        # Left panel: Code with heatmap background
        ax1.set_xlim(0, 10)
        ax1.set_ylim(0, len(lines))
        
        # Create custom colormap
        colors = ['#2d5016', '#8bc34a', '#ffeb3b', '#ff9800', '#f44336']  # Dark green to red
        n_bins = 100
        cmap = LinearSegmentedColormap.from_list('vulnerability', colors, N=n_bins)
        
        # Draw background rectangles for each line
        for i, (line, score) in enumerate(zip(lines, line_predictions)):
            color_intensity = min(score, 1.0)
            
            # Only highlight lines that are above threshold or have significant scores
            if score > threshold:
                # Vulnerable line - highlight with color
                rect = patches.Rectangle((0, len(lines) - i - 1), 10, 1, 
                                       facecolor=cmap(color_intensity), 
                                       alpha=0.8, edgecolor='red', linewidth=2)
                ax1.add_patch(rect)
                
                # Line number
                ax1.text(0.1, len(lines) - i - 0.5, f"{i+1:2d}", 
                        fontsize=10, va='center', ha='left', weight='bold',
                        color='white' if score > 0.6 else 'black')
                
                # Code text
                display_line = line[:80] + "..." if len(line) > 80 else line
                ax1.text(0.8, len(lines) - i - 0.5, display_line, 
                        fontsize=9, va='center', ha='left', fontfamily='monospace',
                        color='white' if score > 0.6 else 'black', weight='bold')
                
                # Vulnerability score
                ax1.text(9.5, len(lines) - i - 0.5, f"{score:.2f}", 
                        fontsize=10, va='center', ha='right', weight='bold',
                        bbox=dict(boxstyle="round,pad=0.3", facecolor='red', alpha=0.7),
                        color='white')
            else:
                # Safe line - light background
                rect = patches.Rectangle((0, len(lines) - i - 1), 10, 1, 
                                       facecolor='#f5f5f5', 
                                       alpha=0.3, edgecolor='gray', linewidth=0.5)
                ax1.add_patch(rect)
                
                # Line number
                ax1.text(0.1, len(lines) - i - 0.5, f"{i+1:2d}", 
                        fontsize=9, va='center', ha='left',
                        color='gray')
                
                # Code text
                display_line = line[:80] + "..." if len(line) > 80 else line
                ax1.text(0.8, len(lines) - i - 0.5, display_line, 
                        fontsize=8, va='center', ha='left', fontfamily='monospace',
                        color='gray')
        
        ax1.set_title(f'{model_type.upper()} Vulnerability Detection\nCode Heatmap (Threshold: {threshold})', 
                     fontsize=14, weight='bold', pad=20)
        ax1.set_xlabel('Code Lines with Vulnerability Scoring', fontsize=12)
        ax1.set_ylabel('Line Number', fontsize=12)
        ax1.set_xticks([])
        ax1.set_yticks([])
        
        # Right panel: Vulnerability score chart - only show vulnerable lines
        vulnerable_lines = [(i, score) for i, score in enumerate(line_predictions) if score > threshold]
        
        if vulnerable_lines:
            y_positions, scores = zip(*vulnerable_lines)
            line_numbers = [i + 1 for i in y_positions]
            
            bars = ax2.barh(range(len(vulnerable_lines)), scores, 
                           color=[cmap(min(score, 1.0)) for score in scores],
                           alpha=0.8, edgecolor='black', linewidth=0.5)
            
            # Add threshold line
            ax2.axvline(x=threshold, color='red', linestyle='--', linewidth=3, alpha=0.8)
            ax2.text(threshold + 0.02, len(vulnerable_lines) * 0.5, f'Threshold: {threshold}', 
                    rotation=90, va='center', ha='left', weight='bold', fontsize=11,
                    bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.8))
            
            ax2.set_yticks(range(len(vulnerable_lines)))
            ax2.set_yticklabels([f'Line {ln}' for ln in line_numbers])
            
            # Add score annotations
            for i, score in enumerate(scores):
                ax2.text(score + 0.02, i, f'{score:.3f}', 
                        va='center', ha='left', fontsize=9, weight='bold')
            
            ax2.set_title(f'Vulnerable Lines Analysis\n{len(vulnerable_lines)} lines flagged', 
                         fontsize=14, weight='bold')
        else:
            ax2.text(0.5, 0.5, 'No vulnerabilities detected\nabove threshold', 
                    transform=ax2.transAxes, ha='center', va='center', 
                    fontsize=16, weight='bold', color='green')
        
        ax2.set_xlabel('Vulnerability Score', fontsize=12)
        ax2.set_xlim(0, 1)
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        return fig

    def analyze_vulnerability_patterns(self, code, predictions, threshold=0.5):
        """Analyze and extract vulnerability patterns"""
        vulnerable_regions = []
        
        for start, end, score in predictions:
            if score > threshold:
                vulnerable_code = code[start:end] if end <= len(code) else code[start:]
                vulnerable_regions.append({
                    'start': start,
                    'end': min(end, len(code)),
                    'score': score,
                    'code': vulnerable_code,
                    'patterns': self.extract_patterns(vulnerable_code)
                })
        
        return vulnerable_regions

    def extract_patterns(self, code):
        """Extract specific vulnerability patterns from code"""
        patterns = []
        
        code_lower = code.lower()
        
        # SQL Injection patterns
        sql_indicators = ['select', 'insert', 'update', 'delete', 'union', 'drop']
        risky_concat = ['+', 'concat', '||']
        if any(sql in code_lower for sql in sql_indicators):
            if any(concat in code for concat in risky_concat):
                patterns.append('SQL_INJECTION')
        
        # XSS patterns
        xss_indicators = ['<script', 'javascript:', 'document.write', 'innerhtml', 'eval(', 'alert(']
        if any(xss in code_lower for xss in xss_indicators):
            patterns.append('XSS')
        
        # Command Injection
        cmd_indicators = ['runtime.exec', 'processbuilder', 'getruntime', '.exec(', 'sh -c']
        if any(cmd in code_lower for cmd in cmd_indicators):
            patterns.append('COMMAND_INJECTION')
        
        # Path Traversal
        path_indicators = ['../', '..\\', 'file.*path', '/etc/', '/bin/']
        if any(path in code_lower for path in path_indicators):
            patterns.append('PATH_TRAVERSAL')
        
        # Deserialization
        deser_indicators = ['objectinputstream', 'readobject', 'deserialize', 'xmldecoder']
        if any(deser in code_lower for deser in deser_indicators):
            patterns.append('UNSAFE_DESERIALIZATION')
        
        return patterns if patterns else ['GENERAL_VULNERABILITY']

    def demonstrate_model(self, model_type, code_key=None, threshold=0.5):
        """Demonstrate vulnerability detection on a code sample using sliding window approach"""
        logger.info(f"Demonstrating {model_type} model...")
        
        # Load model and tokenizer
        model, tokenizer, model_info = self.load_model_and_tokenizer(model_type)
        
        # Get code to analyze
        if code_key and code_key in self.sample_codes:
            code = self.sample_codes[code_key]
            code_name = code_key
        else:
            code = self.sample_codes['sql_injection']  # Default
            code_name = "sql_injection"
        
        logger.info(f"Analyzing {code_name} with {model_type} using sliding window approach")
        
        # Get predictions using sliding window approach
        predictions = self.get_vulnerability_predictions_sliding_window(code, model, tokenizer, model_info)
        
        # Create visualization using the new sliding window method
        fig, vulnerable_lines = self.create_vulnerability_heatmap_sliding(code, predictions, model_info['name'], threshold)
        
        # Save visualization
        output_path = self.demo_path / f"{model_type}_{code_name}_sliding_demo.png"
        fig.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close(fig)
        
        # Analyze patterns for vulnerable lines
        vulnerable_patterns = []
        for vuln_line in vulnerable_lines:
            patterns = self.extract_patterns(vuln_line['content'])
            vulnerable_patterns.extend(patterns)
        
        # Create summary report
        report = {
            'model_type': model_type,
            'model_name': model_info['name'],
            'code_sample': code_name,
            'threshold': threshold,
            'analysis_method': 'sliding_window',
            'total_predictions': len(predictions),
            'vulnerable_lines_count': len(vulnerable_lines),
            'vulnerable_lines': [
                {
                    'line_number': vl['line_number'],
                    'content': vl['content'][:100] + "..." if len(vl['content']) > 100 else vl['content'],
                    'score': vl['score']
                } for vl in vulnerable_lines
            ],
            'max_vulnerability_score': max([vl['score'] for vl in vulnerable_lines]) if vulnerable_lines else 0,
            'avg_vulnerability_score': np.mean([vl['score'] for vl in vulnerable_lines]) if vulnerable_lines else 0,
            'vulnerable_patterns': list(set(vulnerable_patterns)),
            'score_distribution': {
                'critical (>0.8)': len([vl for vl in vulnerable_lines if vl['score'] > 0.8]),
                'high (0.6-0.8)': len([vl for vl in vulnerable_lines if 0.6 < vl['score'] <= 0.8]),
                'medium (0.4-0.6)': len([vl for vl in vulnerable_lines if 0.4 < vl['score'] <= 0.6]),
                'low (0.2-0.4)': len([vl for vl in vulnerable_lines if 0.2 < vl['score'] <= 0.4])
            }
        }
        
        # Save report
        report_path = self.demo_path / f"{model_type}_{code_name}_sliding_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Sliding window demonstration saved to {output_path}")
        logger.info(f"Report saved to {report_path}")
        
        return report, str(output_path)

    def list_samples(self):
        """List all available code samples"""
        print("\nAvailable Java Code Samples:")
        print("=" * 50)
        for key, code in self.sample_codes.items():
            # Extract comment description
            comment_line = next((line for line in code.split('\n') if '// VULNERABLE:' in line or '// SECURE:' in line), '')
            description = comment_line.replace('//', '').strip() if comment_line else 'Code sample'
            print(f"  - {key:20} - {description}")

def main():
    """Main demonstration function"""
    demo = JavaVulnDemo()
    
    if len(sys.argv) < 2:
        print("Java Vulnerability Detection Demo")
        print("=" * 50)
        print("Usage: python java_vuln_demo.py <command> [options]")
        print("\nCommands:")
        print("  demo <model_type> [code_key] [threshold]  - Demo single model")
        print("  list                                      - List available samples")
        print("\nModel types: cnn, bilstm")
        print("Code samples:")
        for key in demo.sample_codes.keys():
            print(f"  • {key}")
        print("\nExamples:")
        print("  python java_vuln_demo.py demo cnn sql_injection 0.5")
        print("  python java_vuln_demo.py demo bilstm xss_vulnerability 0.6")
        return
    
    command = sys.argv[1]
    
    if command == "list":
        demo.list_samples()
    
    elif command == "demo":
        if len(sys.argv) < 3:
            print("Please specify model type: cnn or bilstm")
            return
        
        model_type = sys.argv[2].lower()
        if model_type not in demo.available_models:
            print(f"Invalid model type. Choose: {list(demo.available_models.keys())}")
            return
        
        code_key = sys.argv[3] if len(sys.argv) > 3 else 'sql_injection'
        threshold = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
        
        try:
            report, viz_path = demo.demonstrate_model(model_type, code_key, threshold=threshold)
            print(f"\n{model_type.upper()} Analysis Complete!")
            print("=" * 40)
            print(f"Vulnerable lines found: {report['vulnerable_lines_count']}")
            print(f"Max vulnerability score: {report['max_vulnerability_score']:.3f}")
            print(f"Average score: {report['avg_vulnerability_score']:.3f}")
            print(f"Analysis method: {report['analysis_method']}")
            print(f"Detected patterns: {', '.join(report['vulnerable_patterns'])}")
            
            # Show score distribution
            print(f"\nScore Distribution:")
            for category, count in report['score_distribution'].items():
                if count > 0:
                    print(f"  {category}: {count}")
            
            # Show top vulnerable lines
            if report['vulnerable_lines']:
                print(f"\nTop Vulnerable Lines:")
                for i, vuln_line in enumerate(report['vulnerable_lines'][:5], 1):
                    print(f"  {i}. Line {vuln_line['line_number']:2d}: {vuln_line['score']:.3f}")
                    print(f"     Code: {vuln_line['content'][:60]}...")
            
            print(f"\nVisualization: {viz_path}")
            print(f"Report: {demo.demo_path}/{model_type}_{code_key}_sliding_report.json")
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
    
    else:
        print(f"Unknown command: {command}")
        print("Use 'python java_vuln_demo.py' without arguments for help")

if __name__ == "__main__":
    main()
