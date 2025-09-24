#!/usr/bin/env python3
"""
Enterprise-Grade Java Corpus Builder for Vulnerability Detection - FIXED VERSION
Creates comprehensive Java corpus from multiple high-quality sources
"""

import requests
import json
import os
import zipfile
import logging
import time
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Set
import concurrent.futures
from gensim.models import Word2Vec
from collections import Counter
import pickle
import tempfile
import shutil

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class JavaTokenizer:
    """Simple but effective Java tokenizer without external dependencies"""
    
    def __init__(self):
        # Java keywords and common security-related terms
        self.java_keywords = {
            'abstract', 'assert', 'boolean', 'break', 'byte', 'case', 'catch', 'char',
            'class', 'const', 'continue', 'default', 'do', 'double', 'else', 'enum',
            'extends', 'final', 'finally', 'float', 'for', 'goto', 'if', 'implements',
            'import', 'instanceof', 'int', 'interface', 'long', 'native', 'new', 'package',
            'private', 'protected', 'public', 'return', 'short', 'static', 'strictfp',
            'super', 'switch', 'synchronized', 'this', 'throw', 'throws', 'transient',
            'try', 'void', 'volatile', 'while'
        }
        
        # Security-related terms for vulnerability detection
        self.security_terms = {
            'sql', 'query', 'execute', 'statement', 'connection', 'database',
            'password', 'credential', 'authentication', 'authorization', 'session',
            'cookie', 'header', 'request', 'response', 'input', 'output',
            'file', 'path', 'directory', 'upload', 'download',
            'serialize', 'deserialize', 'object', 'stream',
            'encrypt', 'decrypt', 'hash', 'random', 'secure'
        }
    
    def tokenize_java_code(self, code: str) -> List[str]:
        """Tokenize Java code into meaningful tokens"""
        if not code or not code.strip():
            return []
        
        # Remove comments
        code = re.sub(r'//.*?\n', '\n', code)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        
        # Remove string literals (replace with placeholder)
        code = re.sub(r'"[^"]*"', 'STRING_LITERAL', code)
        code = re.sub(r"'[^']*'", 'CHAR_LITERAL', code)
        
        # Split on common delimiters while preserving important tokens
        tokens = re.findall(r'\b\w+\b|[{}();,.\[\]<>=!&|+\-*/]', code)
        
        # Filter and normalize tokens
        normalized_tokens = []
        for token in tokens:
            token = token.lower().strip()
            if not token:
                continue
                
            # Keep keywords and security terms as-is
            if token in self.java_keywords or token in self.security_terms:
                normalized_tokens.append(token)
            # Keep identifiers (but filter out very short or very long ones)
            elif re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', token) and 2 <= len(token) <= 30:
                normalized_tokens.append(token)
            # Keep numbers as NUM token
            elif re.match(r'^\d+$', token):
                normalized_tokens.append('NUM')
            # Keep important operators
            elif token in {'=', '==', '!=', '<', '>', '<=', '>=', '&&', '||', '!', '+', '-', '*', '/', '%'}:
                normalized_tokens.append(token)
        
        return normalized_tokens

class EnterpriseJavaCorpusBuilder:
    """
    Build comprehensive Java corpus from enterprise-grade sources - FIXED
    """
    
    def __init__(self, github_token: str = None):
        self.github_token = github_token
        self.headers = {}
        if github_token:
            self.headers = {
                'Authorization': f'token {github_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
        
        # Reduced list of most reliable repositories
        self.enterprise_repositories = [
            # Most reliable Apache projects (smaller, faster to clone)
            'apache/commons-lang',
            'apache/commons-collections', 
            'apache/commons-io',
            'apache/commons-codec',
            'apache/maven',
            
            # Spring core (avoid large repos that timeout)
            'spring-projects/spring-framework',
            'spring-projects/spring-boot',
            'spring-projects/spring-security',
            
            # Google utilities
            'google/guava',
            'google/gson',
            
            # Security focused
            'OWASP/java-html-sanitizer',
            
            # Popular libraries
            'square/okhttp',
            'junit-team/junit5',
            'mockito/mockito',
            
            # Additional reliable sources
            'ReactiveX/RxJava',
            'elastic/elasticsearch'
        ]
        
        self.corpus_stats = {
            'total_files': 0,
            'total_lines': 0,
            'total_tokens': 0,
            'repositories_processed': 0,
            'failed_repositories': [],
            'files_written_to_corpus': 0
        }
        
        self.tokenizer = JavaTokenizer()
    
    def clone_repository(self, repo_name: str, base_dir: str = 'corpus_repos') -> str:
        """Clone repository with better error handling and timeout"""
        repo_dir = Path(base_dir) / repo_name.replace('/', '_')
        
        if repo_dir.exists():
            logger.info(f"Repository {repo_name} already exists, using cached version")
            return str(repo_dir)
        
        try:
            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            clone_url = f"https://github.com/{repo_name}.git"
            
            logger.info(f"Cloning {repo_name}...")
            
            # Use shallow clone with reduced timeout
            cmd = [
                'git', 'clone', 
                '--depth', '1', 
                '--single-branch',
                '--no-tags',  # Skip tags for faster clone
                clone_url, 
                str(repo_dir)
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=180  # Reduced timeout to 3 minutes
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully cloned {repo_name}")
                return str(repo_dir)
            else:
                logger.error(f"Failed to clone {repo_name}: {result.stderr}")
                if repo_dir.exists():
                    shutil.rmtree(repo_dir, ignore_errors=True)
                return None
                
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout cloning {repo_name}")
            if repo_dir.exists():
                shutil.rmtree(repo_dir, ignore_errors=True)
            return None
        except Exception as e:
            logger.error(f"Error cloning {repo_name}: {e}")
            if repo_dir.exists():
                shutil.rmtree(repo_dir, ignore_errors=True)
            return None
    
    def extract_java_files(self, repo_dir: str) -> List[str]:
        """Extract Java files with better filtering and validation"""
        java_contents = []
        repo_path = Path(repo_dir)
        
        if not repo_path.exists():
            logger.warning(f"Repository directory does not exist: {repo_dir}")
            return java_contents
        
        # Exclude patterns for better filtering
        exclude_patterns = {
            'test', 'tests', 'target', 'build', 'generated', 'gen',
            '.git', 'node_modules', 'examples', 'samples', 'demo',
            'benchmark', 'docs', 'documentation'
        }
        
        java_files_found = 0
        
        try:
            for java_file in repo_path.rglob('*.java'):
                # Skip if in excluded directory
                if any(exclude in str(java_file).lower() for exclude in exclude_patterns):
                    continue
                
                # Skip very large files (likely generated)
                try:
                    file_size = java_file.stat().st_size
                    if file_size > 200_000:  # 200KB limit
                        continue
                    if file_size < 100:  # Skip very small files
                        continue
                except OSError:
                    continue
                
                try:
                    with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Basic quality filters
                        if len(content.strip()) < 200:  # Skip very short files
                            continue
                        if content.count('import ') > 50:  # Skip likely generated files
                            continue
                        if 'generated' in content.lower()[:500]:  # Check for generated code markers
                            continue
                        
                        java_contents.append(content)
                        java_files_found += 1
                        
                        # Limit files per repo to prevent memory issues
                        if java_files_found >= 100:
                            break
                            
                except Exception as e:
                    logger.debug(f"Could not read {java_file}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error processing repository {repo_dir}: {e}")
        
        logger.info(f"Extracted {len(java_contents)} Java files from {repo_dir}")
        return java_contents
    
    def build_comprehensive_corpus(self, output_file: str = 'comprehensive_java_corpus.txt',
                                 max_repos: int = 15) -> str:
        """Build comprehensive Java corpus - FIXED VERSION"""
        logger.info("Building comprehensive Java corpus from enterprise repositories...")
        
        os.makedirs('corpus_repos', exist_ok=True)
        all_java_content = []
        
        # Process repositories sequentially to avoid timeout issues
        successful_repos = 0
        for i, repo in enumerate(self.enterprise_repositories[:max_repos]):
            logger.info(f"Processing repository {i+1}/{min(max_repos, len(self.enterprise_repositories))}: {repo}")
            
            try:
                repo_dir = self.clone_repository(repo)
                if repo_dir:
                    java_files = self.extract_java_files(repo_dir)
                    if java_files:
                        all_java_content.extend(java_files)
                        self.corpus_stats['repositories_processed'] += 1
                        successful_repos += 1
                        logger.info(f"Successfully processed {repo}: {len(java_files)} files")
                    else:
                        self.corpus_stats['failed_repositories'].append(repo)
                        logger.warning(f"No Java files found in {repo}")
                else:
                    self.corpus_stats['failed_repositories'].append(repo)
                    
            except Exception as e:
                logger.error(f"Repository {repo} failed: {e}")
                self.corpus_stats['failed_repositories'].append(repo)
            
            # Add small delay to be nice to GitHub
            time.sleep(2)
        
        # Add existing vulnerability samples if available
        logger.info("Adding existing vulnerability samples to corpus...")
        existing_samples = self._load_existing_samples()
        if existing_samples:
            all_java_content.extend(existing_samples)
            logger.info(f"Added {len(existing_samples)} existing vulnerability samples")
        
        # Ensure we have content
        if not all_java_content:
            logger.error("No Java content collected! Creating minimal corpus from built-in samples...")
            all_java_content = self._create_minimal_corpus()
        
        # Write comprehensive corpus with validation
        logger.info(f"Writing corpus with {len(all_java_content)} files...")
        files_written = 0
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for i, content in enumerate(all_java_content):
                cleaned = self._clean_java_content(content)
                if cleaned and len(cleaned.strip()) > 100:
                    f.write(cleaned + '\n\n')
                    files_written += 1
                    if i % 100 == 0:
                        logger.info(f"Written {files_written} files to corpus...")
        
        self.corpus_stats['files_written_to_corpus'] = files_written
        self.corpus_stats['total_files'] = len(all_java_content)
        
        # Validate corpus was created
        if os.path.exists(output_file):
            corpus_size = os.path.getsize(output_file)
            logger.info(f"Corpus file created: {output_file} ({corpus_size:,} bytes)")
            
            if corpus_size == 0:
                logger.error("Corpus file is empty! Creating emergency backup corpus...")
                self._create_emergency_corpus(output_file)
        else:
            logger.error("Corpus file was not created!")
            return None
        
        # Generate corpus statistics
        self._generate_corpus_stats(output_file)
        
        logger.info(f"Comprehensive corpus built: {output_file}")
        logger.info(f"Processed {successful_repos} repositories successfully")
        logger.info(f"Files written to corpus: {files_written}")
        
        return output_file
    
    def _create_minimal_corpus(self) -> List[str]:
        """Create minimal corpus from built-in Java samples"""
        logger.info("Creating minimal corpus from built-in samples...")
        
        minimal_samples = [
            """
            package com.example.security;
            import java.sql.Connection;
            import java.sql.Statement;
            import java.sql.ResultSet;
            
            public class VulnerableExample {
                public void sqlInjection(String userInput) {
                    String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
                    Statement stmt = connection.createStatement();
                    ResultSet rs = stmt.executeQuery(query);
                }
                
                public void pathTraversal(String fileName) {
                    File file = new File("/uploads/" + fileName);
                    FileInputStream fis = new FileInputStream(file);
                }
            }
            """,
            """
            package com.example.web;
            import javax.servlet.http.HttpServlet;
            import javax.servlet.http.HttpServletRequest;
            import javax.servlet.http.HttpServletResponse;
            
            public class XSSVulnerable extends HttpServlet {
                protected void doGet(HttpServletRequest request, HttpServletResponse response) {
                    String userInput = request.getParameter("input");
                    response.getWriter().println("<html><body>" + userInput + "</body></html>");
                }
                
                public void commandInjection(String command) {
                    Runtime runtime = Runtime.getRuntime();
                    Process process = runtime.exec("ls " + command);
                }
            }
            """,
            """
            package com.example.crypto;
            import java.security.MessageDigest;
            import javax.crypto.Cipher;
            
            public class CryptoExample {
                public String weakHash(String password) {
                    MessageDigest md = MessageDigest.getInstance("MD5");
                    byte[] hash = md.digest(password.getBytes());
                    return new String(hash);
                }
                
                public void weakEncryption(String data) throws Exception {
                    Cipher cipher = Cipher.getInstance("DES");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    byte[] encrypted = cipher.doFinal(data.getBytes());
                }
            }
            """
        ]
        
        return minimal_samples
    
    def _create_emergency_corpus(self, output_file: str):
        """Create emergency corpus if main process fails"""
        logger.info("Creating emergency corpus...")
        
        emergency_content = self._create_minimal_corpus()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for content in emergency_content:
                f.write(content + '\n\n')
        
        logger.info(f"Emergency corpus created with {len(emergency_content)} samples")
    
    def _load_existing_samples(self) -> List[str]:
        """Load existing vulnerability samples with better error handling"""
        existing_files = [
            'java_vulnerability_dataset.json',
            'final_all_samples.json',
            'combined_java_samples.json',
            'vulnerability_samples.json'
        ]
        
        samples = []
        for file_path in existing_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                        # Handle different data structures
                        if isinstance(data, list):
                            for sample in data:
                                if isinstance(sample, dict):
                                    if 'tokens' in sample:
                                        code = ' '.join(sample['tokens'])
                                        samples.append(code)
                                    elif 'code' in sample:
                                        samples.append(sample['code'])
                                    elif 'content' in sample:
                                        samples.append(sample['content'])
                                elif isinstance(sample, str):
                                    samples.append(sample)
                        elif isinstance(data, dict):
                            # Handle dictionary structure
                            for key, value in data.items():
                                if isinstance(value, str) and len(value) > 100:
                                    samples.append(value)
                                    
                except Exception as e:
                    logger.warning(f"Could not load {file_path}: {e}")
        
        logger.info(f"Loaded {len(samples)} existing samples")
        return samples
    
    def _clean_java_content(self, content: str) -> str:
        """Clean and normalize Java content for corpus"""
        if not content or not content.strip():
            return None
        
        # Remove excessive whitespace but preserve structure
        content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)  # Remove excessive newlines
        content = re.sub(r'[ \t]+', ' ', content)  # Normalize spaces
        
        # Remove very long lines (likely generated code)
        lines = content.split('\n')
        cleaned_lines = []
        
        for line in lines:
            line = line.strip()
            if len(line) < 300 and line:  # Keep reasonable lines
                cleaned_lines.append(line)
        
        # Must have reasonable amount of content
        if len(cleaned_lines) < 3:
            return None
        
        result = '\n'.join(cleaned_lines)
        
        # Final validation
        if len(result.strip()) < 100:
            return None
        
        return result
    
    def _generate_corpus_stats(self, corpus_file: str):
        """Generate detailed corpus statistics"""
        try:
            with open(corpus_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self.corpus_stats['total_tokens'] = len(content.split())
                self.corpus_stats['total_lines'] = content.count('\n')
                self.corpus_stats['corpus_size_bytes'] = len(content.encode('utf-8'))
        except Exception as e:
            logger.warning(f"Could not generate corpus stats: {e}")
        
        stats_file = corpus_file.replace('.txt', '_stats.json')
        try:
            with open(stats_file, 'w') as f:
                json.dump(self.corpus_stats, f, indent=2)
            logger.info(f"Corpus statistics saved to {stats_file}")
        except Exception as e:
            logger.warning(f"Could not save corpus stats: {e}")
    
    def train_enhanced_word2vec(self, corpus_file: str, model_output: str = 'enhanced_java_word2vec.model',
                              vector_size: int = 200, window: int = 10, min_count: int = 2) -> Word2Vec:
        """Train enhanced Word2Vec model with better error handling"""
        logger.info("Training enhanced Word2Vec model on comprehensive corpus...")
        
        # Validate corpus file exists and has content
        if not os.path.exists(corpus_file):
            logger.error(f"Corpus file {corpus_file} does not exist!")
            return None
        
        corpus_size = os.path.getsize(corpus_file)
        if corpus_size == 0:
            logger.error(f"Corpus file {corpus_file} is empty!")
            return None
        
        logger.info(f"Corpus file size: {corpus_size:,} bytes")
        
        # Process corpus with improved tokenization
        sentences = []
        logger.info("Tokenizing comprehensive corpus...")
        
        try:
            with open(corpus_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Split into chunks and process
            content_chunks = [chunk.strip() for chunk in content.split('\n\n') if chunk.strip()]
            logger.info(f"Processing {len(content_chunks)} content chunks...")
            
            valid_sentences = 0
            for i, chunk in enumerate(content_chunks):
                if i % 500 == 0:
                    logger.info(f"Processed {i}/{len(content_chunks)} chunks, created {valid_sentences} sentences")
                
                if len(chunk.strip()) > 50:  # Skip very short chunks
                    try:
                        tokens = self.tokenizer.tokenize_java_code(chunk)
                        
                        if len(tokens) >= 5:  # Must have reasonable length
                            sentences.append(tokens)
                            valid_sentences += 1
                            
                    except Exception as e:
                        logger.debug(f"Tokenization failed for chunk {i}: {e}")
                        continue
            
            logger.info(f"Created {len(sentences)} training sentences")
            
            if len(sentences) == 0:
                logger.error("No valid sentences created for training!")
                return None
            
            # Train Word2Vec model with conservative parameters
            logger.info("Training Word2Vec model...")
            
            model = Word2Vec(
                sentences=sentences,
                vector_size=vector_size,
                window=window,
                min_count=min_count,
                workers=1,  # Single worker to avoid issues
                epochs=15,
                sg=1,  # Skip-gram
                hs=0,  # Use negative sampling
                negative=10,
                alpha=0.025,
                min_alpha=0.0001,
                compute_loss=True
            )
            
            # Save model
            model.save(model_output)
            logger.info(f"Enhanced Word2Vec model saved: {model_output}")
            
            # Model statistics
            vocab_size = len(model.wv.key_to_index)
            logger.info(f"Vocabulary size: {vocab_size}")
            
            if vocab_size == 0:
                logger.error("Model has empty vocabulary!")
                return None
            
            # Save vocabulary analysis
            vocab_stats = {
                'vocabulary_size': vocab_size,
                'vector_dimension': vector_size,
                'training_sentences': len(sentences),
                'total_training_tokens': sum(len(s) for s in sentences),
                'min_count_threshold': min_count,
                'window_size': window,
                'corpus_chunks_processed': len(content_chunks),
                'valid_sentences_created': valid_sentences
            }
            
            vocab_stats_file = model_output.replace('.model', '_vocab_stats.json')
            with open(vocab_stats_file, 'w') as f:
                json.dump(vocab_stats, f, indent=2)
            
            logger.info(f"Vocabulary statistics saved to {vocab_stats_file}")
            return model
            
        except Exception as e:
            logger.error(f"Error training Word2Vec model: {e}")
            return None

def main():
    """Build comprehensive Java corpus and train enhanced Word2Vec - FIXED"""
    logger.info("Starting enhanced Java corpus building process...")
    
    try:
        # Initialize builder
        builder = EnterpriseJavaCorpusBuilder()
        
        # Build comprehensive corpus
        corpus_file = builder.build_comprehensive_corpus(
            output_file='comprehensive_java_corpus.txt',
            max_repos=12  # Reduced to prevent timeouts
        )
        
        if not corpus_file or not os.path.exists(corpus_file):
            logger.error("Failed to create corpus file!")
            return
        
        # Validate corpus has content
        corpus_size = os.path.getsize(corpus_file)
        if corpus_size == 0:
            logger.error("Corpus file is empty!")
            return
        
        logger.info(f"Corpus created successfully: {corpus_size:,} bytes")
        
        # Train enhanced Word2Vec model
        model = builder.train_enhanced_word2vec(
            corpus_file=corpus_file,
            model_output='enhanced_java_word2vec.model',
            vector_size=200,  # Reduced for stability
            window=10,
            min_count=2  # Lower threshold to capture more vocabulary
        )
        
        if model:
            logger.info("Enhanced Java corpus and Word2Vec model building complete!")
            print("✅ SUCCESS: Enhanced Java corpus and Word2Vec model building complete!")
        else:
            logger.error("Failed to train Word2Vec model!")
            print("❌ FAILED: Word2Vec model training failed!")
            
    except Exception as e:
        logger.error(f"Main process failed: {e}")
        print(f"❌ FAILED: {e}")

if __name__ == "__main__":
    main()