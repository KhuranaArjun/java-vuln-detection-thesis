#!/usr/bin/env python3
"""
Java Vulnerability Dataset Generator - Step 2: Dataset Processor
Based on Laura Wartschinski's VUDENC methodology

This script processes the scraped vulnerability commits to create a labeled
dataset for training vulnerability detection models.
"""

import json
import re
import os
import requests
from typing import List, Dict, Tuple, Optional
import logging
from urllib.parse import urlparse
import hashlib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    import javalang
    from javalang.tokenizer import tokenize, LexerError
    JAVALANG_AVAILABLE = True
except ImportError:
    logger.warning("javalang not available, using fallback tokenization")
    JAVALANG_AVAILABLE = False

from dataclasses import dataclass

@dataclass
class CodeSample:
    """Represents a code sample with vulnerability labels"""
    tokens: List[str]
    labels: List[int]  # 1 for vulnerable, 0 for not vulnerable
    context_window: int
    filename: str
    commit_sha: str
    vulnerability_type: str
    repository: str

class JavaDatasetProcessor:
    def __init__(self, context_window: int = 10):
        """
        Initialize the dataset processor
        
        Args:
            context_window: Number of tokens before and after each token for context
        """
        self.context_window = context_window
        
        # Java vulnerability patterns (following Wartschinski's classification approach)
        self.vulnerability_patterns = {
            'sql_injection': [
                'prepareStatement', 'createStatement', 'executeQuery', 'executeUpdate',
                'Statement', 'PreparedStatement', 'query', 'execute'
            ],
            'xss': [
                'getParameter', 'getHeader', 'getCookie', 'setAttribute', 
                'response.getWriter', 'out.print', 'RequestDispatcher'
            ],
            'command_injection': [
                'Runtime.exec', 'ProcessBuilder', 'Process', 'exec',
                'getRuntime', 'start'
            ],
            'deserialization': [
                'ObjectInputStream', 'readObject', 'deserialize', 'Serializable',
                'readUnshared', 'ObjectInput'
            ],
            'path_traversal': [
                'File', 'FileInputStream', 'FileOutputStream', 'Path', 'Paths',
                'getCanonicalPath', 'getAbsolutePath', 'resolve'
            ],
            'xxe': [
                'DocumentBuilder', 'SAXParser', 'XMLReader', 'TransformerFactory',
                'DocumentBuilderFactory', 'SAXParserFactory', 'XMLInputFactory'
            ],
            'csrf': [
                'HttpSession', 'getSession', 'CSRF', 'token', 'csrf',
                'RequestMapping', 'PostMapping'
            ]
        }
    
    def tokenize_java_code(self, code: str) -> List[str]:
        """
        Tokenize Java code using javalang tokenizer or fallback
        
        Args:
            code: Java source code string
            
        Returns:
            List of tokens
        """
        if JAVALANG_AVAILABLE:
            try:
                tokens = list(tokenize(code))
                return [token.value for token in tokens]
            except (LexerError, Exception) as e:
                logger.warning(f"Tokenization error: {e}")
                return self.simple_tokenize(code)
        else:
            return self.simple_tokenize(code)
    
    def simple_tokenize(self, code: str) -> List[str]:
        """
        Simple fallback tokenization for malformed Java code
        """
        # Remove comments and strings for simpler tokenization
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'".*?"', 'STRING_LITERAL', code)
        code = re.sub(r"'.*?'", 'CHAR_LITERAL', code)
        
        # Split on common Java delimiters
        tokens = re.findall(r'\b\w+\b|[{}();,=+\-*/<>!&|]', code)
        return [token for token in tokens if token.strip()]
    
    def parse_diff_hunks(self, patch: str) -> List[Dict]:
        """
        Parse git diff patch to extract added/removed lines
        Following Wartschinski's approach to identify vulnerable code changes
        
        Args:
            patch: Git diff patch string
            
        Returns:
            List of hunks with line information
        """
        hunks = []
        lines = patch.split('\n')
        
        current_hunk = None
        old_line_num = 0
        new_line_num = 0
        
        for line in lines:
            # Parse hunk header (e.g., @@ -10,7 +10,8 @@)
            hunk_match = re.match(r'@@\s+-(\d+),?\d*\s+\+(\d+),?\d*\s+@@', line)
            if hunk_match:
                if current_hunk:
                    hunks.append(current_hunk)
                
                old_line_num = int(hunk_match.group(1))
                new_line_num = int(hunk_match.group(2))
                
                current_hunk = {
                    'old_start': old_line_num,
                    'new_start': new_line_num,
                    'context_lines': [],
                    'removed_lines': [],
                    'added_lines': [],
                    'line_mappings': []
                }
                continue
            
            if current_hunk is None:
                continue
            
            # Process diff lines
            if line.startswith('+') and not line.startswith('+++'):
                # Added line (potentially fixed code)
                content = line[1:]
                current_hunk['added_lines'].append({
                    'content': content,
                    'new_line_num': new_line_num
                })
                current_hunk['line_mappings'].append(('added', new_line_num, content))
                new_line_num += 1
                
            elif line.startswith('-') and not line.startswith('---'):
                # Removed line (potentially vulnerable code)
                content = line[1:]
                current_hunk['removed_lines'].append({
                    'content': content,
                    'old_line_num': old_line_num
                })
                current_hunk['line_mappings'].append(('removed', old_line_num, content))
                old_line_num += 1
                
            elif line.startswith(' '):
                # Context line
                content = line[1:]
                current_hunk['context_lines'].append({
                    'content': content,
                    'old_line_num': old_line_num,
                    'new_line_num': new_line_num
                })
                current_hunk['line_mappings'].append(('context', new_line_num, content))
                old_line_num += 1
                new_line_num += 1
        
        if current_hunk:
            hunks.append(current_hunk)
        
        return hunks
    
    def classify_vulnerability_type(self, code: str, commit_message: str) -> str:
        """
        Classify the type of vulnerability based on code patterns and commit message
        """
        code_lower = code.lower()
        message_lower = commit_message.lower()
        
        # Check patterns in both code and commit message
        for vuln_type, patterns in self.vulnerability_patterns.items():
            score = 0
            
            # Check code patterns
            for pattern in patterns:
                if pattern.lower() in code_lower:
                    score += 2
            
            # Check commit message
            vuln_keywords = {
                'sql_injection': ['sql', 'injection', 'sqli'],
                'xss': ['xss', 'cross-site', 'script'],
                'command_injection': ['command', 'injection', 'exec'],
                'deserialization': ['deserialization', 'serialize'],
                'path_traversal': ['path', 'traversal', 'directory'],
                'xxe': ['xxe', 'xml', 'external', 'entity'],
                'csrf': ['csrf', 'cross-site', 'request', 'forgery']
            }
            
            if vuln_type in vuln_keywords:
                for keyword in vuln_keywords[vuln_type]:
                    if keyword in message_lower:
                        score += 1
            
            if score >= 2:
                return vuln_type
        
        return 'unknown'
    
    def create_labeled_samples(self, hunks: List[Dict], filename: str, 
                             commit_sha: str, commit_message: str, 
                             repository: str) -> List[CodeSample]:
        """
        Create labeled training samples from diff hunks
        Following Wartschinski's token-level labeling approach
        
        Args:
            hunks: Parsed diff hunks
            filename: Source file name
            commit_sha: Git commit SHA
            commit_message: Commit message
            repository: Repository name
            
        Returns:
            List of labeled code samples
        """
        samples = []
        
        for hunk in hunks:
            # Combine all lines to create context
            all_lines = []
            vulnerability_labels = []
            
            # Add context lines (not vulnerable)
            for line_info in hunk['context_lines']:
                all_lines.append(line_info['content'])
                vulnerability_labels.append(0)
            
            # Add removed lines (vulnerable code)
            for line_info in hunk['removed_lines']:
                all_lines.append(line_info['content'])
                vulnerability_labels.append(1)  # Mark as vulnerable
            
            # Add added lines (fixed code, not vulnerable)
            for line_info in hunk['added_lines']:
                all_lines.append(line_info['content'])
                vulnerability_labels.append(0)
            
            # Tokenize all lines together
            combined_code = '\n'.join(all_lines)
            tokens = self.tokenize_java_code(combined_code)
            
            if len(tokens) < 5:  # Skip very short code snippets
                continue
            
            # Create token-level labels based on line labels
            token_labels = self.map_line_labels_to_tokens(
                all_lines, vulnerability_labels, tokens
            )
            
            # Classify vulnerability type
            vuln_type = self.classify_vulnerability_type(combined_code, commit_message)
            
            # Create sliding window samples
            window_samples = self.create_sliding_windows(
                tokens, token_labels, filename, commit_sha, 
                vuln_type, repository
            )
            
            samples.extend(window_samples)
        
        return samples
    
    def map_line_labels_to_tokens(self, lines: List[str], 
                                 line_labels: List[int], 
                                 tokens: List[str]) -> List[int]:
        """
        Map line-level vulnerability labels to token-level labels
        """
        token_labels = []
        token_idx = 0
        
        for line_idx, line in enumerate(lines):
            line_tokens = self.tokenize_java_code(line)
            line_label = line_labels[line_idx] if line_idx < len(line_labels) else 0
            
            # Assign the line's label to all its tokens
            for _ in line_tokens:
                if token_idx < len(tokens):
                    token_labels.append(line_label)
                    token_idx += 1
        
        # Fill remaining tokens with 0 (not vulnerable)
        while len(token_labels) < len(tokens):
            token_labels.append(0)
        
        return token_labels[:len(tokens)]
    
    def create_sliding_windows(self, tokens: List[str], labels: List[int],
                              filename: str, commit_sha: str, 
                              vuln_type: str, repository: str) -> List[CodeSample]:
        """
        Create sliding window samples for training
        Following Wartschinski's context window approach
        """
        samples = []
        window_size = 2 * self.context_window + 1
        
        if len(tokens) < window_size:
            # If code is shorter than window, use the entire sequence
            return [CodeSample(
                tokens=tokens,
                labels=labels,
                context_window=self.context_window,
                filename=filename,
                commit_sha=commit_sha,
                vulnerability_type=vuln_type,
                repository=repository
            )]
        
        # Create sliding windows
        for i in range(len(tokens) - window_size + 1):
            window_tokens = tokens[i:i + window_size]
            window_labels = labels[i:i + window_size]
            
            # Only include windows that contain at least one vulnerable token
            if sum(window_labels) > 0:
                samples.append(CodeSample(
                    tokens=window_tokens,
                    labels=window_labels,
                    context_window=self.context_window,
                    filename=filename,
                    commit_sha=commit_sha,
                    vulnerability_type=vuln_type,
                    repository=repository
                ))
        
        return samples
    
    def process_commits_dataset(self, commits_file: str, 
                               output_file: str = 'java_vulnerability_dataset.json',
                               max_samples_per_commit: int = 50) -> List[CodeSample]:
        """
        Process the collected commits to create the final training dataset
        
        Args:
            commits_file: JSON file with scraped commits
            output_file: Output file for the processed dataset
            max_samples_per_commit: Maximum samples to extract per commit
            
        Returns:
            List of processed code samples
        """
        logger.info("Loading commits data...")
        with open(commits_file, 'r') as f:
            commits_data = json.load(f)
        
        logger.info(f"Processing {len(commits_data)} commits...")
        
        all_samples = []
        vulnerability_type_counts = {}
        
        for i, commit_data in enumerate(commits_data):
            logger.info(f"Processing commit {i+1}/{len(commits_data)}: {commit_data['sha'][:8]}")
            
            commit_samples = []
            
            # Process each Java file in the commit
            for java_file in commit_data['java_files']:
                if 'patch' not in java_file:
                    continue
                
                # Parse the diff
                hunks = self.parse_diff_hunks(java_file['patch'])
                
                if not hunks:
                    continue
                
                # Create labeled samples
                file_samples = self.create_labeled_samples(
                    hunks=hunks,
                    filename=java_file['filename'],
                    commit_sha=commit_data['sha'],
                    commit_message=commit_data['message'],
                    repository=commit_data['repository']
                )
                
                commit_samples.extend(file_samples)
            
            # Limit samples per commit to avoid overrepresentation
            if len(commit_samples) > max_samples_per_commit:
                commit_samples = commit_samples[:max_samples_per_commit]
            
            all_samples.extend(commit_samples)
            
            # Track vulnerability types
            for sample in commit_samples:
                vuln_type = sample.vulnerability_type
                vulnerability_type_counts[vuln_type] = vulnerability_type_counts.get(vuln_type, 0) + 1
        
        logger.info(f"Created {len(all_samples)} training samples")
        logger.info("Vulnerability type distribution:")
        for vuln_type, count in sorted(vulnerability_type_counts.items()):
            logger.info(f"  {vuln_type}: {count} samples")
        
        # Convert to serializable format
        dataset = []
        for sample in all_samples:
            dataset.append({
                'tokens': sample.tokens,
                'labels': sample.labels,
                'context_window': sample.context_window,
                'filename': sample.filename,
                'commit_sha': sample.commit_sha,
                'vulnerability_type': sample.vulnerability_type,
                'repository': sample.repository,
                'sample_id': hashlib.md5(
                    (sample.commit_sha + sample.filename + str(sample.tokens)).encode()
                ).hexdigest()[:8]
            })
        
        # Save the dataset
        logger.info(f"Saving dataset to {output_file}...")
        with open(output_file, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        # Save statistics
        stats = {
            'total_samples': len(dataset),
            'total_commits': len(commits_data),
            'vulnerability_type_distribution': vulnerability_type_counts,
            'average_tokens_per_sample': sum(len(s['tokens']) for s in dataset) / len(dataset) if dataset else 0,
            'context_window': self.context_window
        }
        
        with open(f"{output_file.replace('.json', '_stats.json')}", 'w') as f:
            json.dump(stats, f, indent=2)
        
        logger.info("Dataset processing complete!")
        return all_samples

# Example usage
if __name__ == "__main__":
    processor = JavaDatasetProcessor(context_window=10)
    
    # Process the scraped commits
    samples = processor.process_commits_dataset(
        commits_file='java_vulnerability_commits.json',
        output_file='java_vulnerability_dataset.json',
        max_samples_per_commit=30
    )
    
    print(f"Created dataset with {len(samples)} samples")