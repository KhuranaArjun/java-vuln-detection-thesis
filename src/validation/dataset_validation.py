#!/usr/bin/env python3
"""
Expert Validation Pipeline for Dataset Quality Enhancement
Addresses duplicate samples, improves vulnerability classification, and creates high-quality dataset
"""

import json
import hashlib
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Tuple, Set
import logging
from collections import Counter, defaultdict
import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import DBSCAN
import matplotlib.pyplot as plt
import seaborn as sns

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ExpertValidationPipeline:
    def __init__(self, dataset_path: str, output_dir: str = "expert_validation_results"):
        """
        Initialize Expert Validation Pipeline
        
        Args:
            dataset_path: Path to the dataset file
            output_dir: Directory to save validation results
        """
        self.dataset_path = Path(dataset_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Load dataset
        self.data = self.load_dataset()
        
        # Vulnerability classification patterns (Java-specific)
        self.vulnerability_patterns = {
            'SQL_INJECTION': [
                r'(?i)(select|insert|update|delete).*\+.*\w+',
                r'(?i)statement.*createstatement.*executequery',
                r'(?i)query.*\+.*user.*input',
                r'(?i)sql.*injection',
                r'(?i)preparedstatement.*setstring.*\?'
            ],
            'XSS': [
                r'(?i)response.*getwriter.*print',
                r'(?i)document\.write.*user',
                r'(?i)innerhtml.*\+',
                r'(?i)cross.*site.*scripting',
                r'(?i)<script>.*user'
            ],
            'COMMAND_INJECTION': [
                r'(?i)runtime.*exec.*\+',
                r'(?i)processbuilder.*command',
                r'(?i)system.*exec.*user',
                r'(?i)command.*injection'
            ],
            'PATH_TRAVERSAL': [
                r'(?i)\.\./.*\.\.',
                r'(?i)file.*path.*\+.*user',
                r'(?i)directory.*traversal',
                r'(?i)path.*manipulation'
            ],
            'ACCESS_CONTROL': [
                r'(?i)authorization.*bypass',
                r'(?i)access.*control',
                r'(?i)permission.*check',
                r'(?i)role.*based'
            ],
            'INPUT_VALIDATION': [
                r'(?i)input.*validation',
                r'(?i)sanitize.*input',
                r'(?i)validate.*parameter',
                r'(?i)user.*input.*check'
            ]
        }
        
        logger.info(f"Loaded {len(self.data)} samples for expert validation")
    
    def load_dataset(self) -> List[Dict]:
        """Load dataset using the same logic as cross-validation script"""
        with open(self.dataset_path, 'r') as f:
            raw_data = json.load(f)
        
        # Handle dictionary format
        data_samples = []
        if isinstance(raw_data, dict):
            # Look for training data key
            for key, value in raw_data.items():
                if isinstance(value, list) and len(value) > 0:
                    first_item = value[0]
                    if isinstance(first_item, dict):
                        sample_keys = list(first_item.keys())
                        code_indicators = ['code', 'vulnerable_code', 'code_before', 'source']
                        if any(indicator in sample_keys for indicator in code_indicators):
                            data_samples = value
                            logger.info(f"Found {len(value)} samples in key: '{key}'")
                            break
        
        # Process samples
        processed_data = []
        for i, sample in enumerate(data_samples):
            if not isinstance(sample, dict):
                continue
                
            processed_sample = {}
            
            # Map field names
            field_mappings = {
                'code': ['code', 'code_before', 'vulnerable_code', 'source_code', 'content'],
                'vulnerability_type': ['vulnerability_type', 'vuln_type', 'type', 'class', 'category', 'label'],
                'repository': ['repository', 'repo', 'repo_name', 'project', 'source'],
                'commit_date': ['commit_date', 'date', 'timestamp', 'created_at', 'time']
            }
            
            for standard_field, possible_names in field_mappings.items():
                for possible_name in possible_names:
                    if possible_name in sample:
                        processed_sample[standard_field] = sample[possible_name]
                        break
            
            # Skip samples without code
            if 'code' not in processed_sample:
                continue
                
            # Set defaults
            if 'vulnerability_type' not in processed_sample:
                processed_sample['vulnerability_type'] = 'UNKNOWN'
            if 'repository' not in processed_sample:
                processed_sample['repository'] = f'unknown_repo_{i}'
            if 'commit_date' not in processed_sample:
                processed_sample['commit_date'] = datetime.now()
            
            # Add unique identifier
            processed_sample['sample_id'] = i
            processed_sample['code_hash'] = hashlib.md5(processed_sample['code'].encode()).hexdigest()
            
            processed_data.append(processed_sample)
        
        return processed_data
    
    def detect_exact_duplicates(self) -> Dict[str, List[int]]:
        """Detect exact duplicate code samples"""
        code_hash_to_indices = defaultdict(list)
        
        for i, sample in enumerate(self.data):
            code_hash = sample['code_hash']
            code_hash_to_indices[code_hash].append(i)
        
        # Find duplicates
        exact_duplicates = {
            hash_val: indices for hash_val, indices in code_hash_to_indices.items() 
            if len(indices) > 1
        }
        
        logger.info(f"Found {len(exact_duplicates)} groups of exact duplicates")
        logger.info(f"Total duplicate instances: {sum(len(indices) for indices in exact_duplicates.values())}")
        
        return exact_duplicates
    
    def detect_semantic_duplicates(self, similarity_threshold: float = 0.85) -> List[Tuple[int, int, float]]:
        """Detect semantically similar code samples using TF-IDF"""
        logger.info("Computing semantic similarity for duplicate detection...")
        
        # Extract code content
        code_samples = [sample['code'] for sample in self.data]
        
        # Use TF-IDF with code-specific preprocessing
        def preprocess_code(code):
            # Remove comments
            code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
            code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
            # Remove string literals to focus on structure
            code = re.sub(r'"[^"]*"', '"STRING"', code)
            code = re.sub(r"'[^']*'", "'STRING'", code)
            return code
        
        preprocessed_code = [preprocess_code(code) for code in code_samples]
        
        # Compute TF-IDF with n-grams to capture code patterns
        vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            min_df=2,
            max_df=0.8,
            token_pattern=r'[a-zA-Z_$][a-zA-Z0-9_$]*|[^\w\s]'
        )
        
        tfidf_matrix = vectorizer.fit_transform(preprocessed_code)
        
        # Compute pairwise similarities (only for samples with high enough similarity)
        similarities = []
        logger.info("Computing pairwise similarities...")
        
        # Use batch processing to handle large datasets
        batch_size = 1000
        for i in range(0, len(self.data), batch_size):
            batch_end = min(i + batch_size, len(self.data))
            batch_similarities = cosine_similarity(
                tfidf_matrix[i:batch_end], 
                tfidf_matrix
            )
            
            for batch_idx, sim_row in enumerate(batch_similarities):
                global_idx_i = i + batch_idx
                for j, similarity in enumerate(sim_row):
                    if j > global_idx_i and similarity >= similarity_threshold:
                        similarities.append((global_idx_i, j, similarity))
        
        logger.info(f"Found {len(similarities)} semantic duplicate pairs")
        return similarities
    
    def enhance_vulnerability_classification(self) -> Dict[str, Any]:
        """Enhance vulnerability classification using pattern matching"""
        logger.info("Enhancing vulnerability classification...")
        
        classification_changes = {
            'enhanced_count': 0,
            'changes_by_type': defaultdict(int),
            'confidence_scores': []
        }
        
        for sample in self.data:
            if sample['vulnerability_type'] in ['UNKNOWN', 'OTHER_SECURITY']:
                code = sample['code'].lower()
                best_match = None
                best_score = 0
                
                # Check against all patterns
                for vuln_type, patterns in self.vulnerability_patterns.items():
                    score = 0
                    for pattern in patterns:
                        if re.search(pattern, code):
                            score += 1
                    
                    # Calculate confidence score
                    confidence = score / len(patterns) if patterns else 0
                    
                    if confidence > best_score and confidence >= 0.3:  # Minimum confidence
                        best_match = vuln_type
                        best_score = confidence
                
                # Update classification if confident enough
                if best_match and best_score >= 0.4:
                    original_type = sample['vulnerability_type']
                    sample['vulnerability_type'] = best_match
                    sample['classification_confidence'] = best_score
                    
                    classification_changes['enhanced_count'] += 1
                    classification_changes['changes_by_type'][f"{original_type} -> {best_match}"] += 1
                    classification_changes['confidence_scores'].append(best_score)
        
        logger.info(f"Enhanced classification for {classification_changes['enhanced_count']} samples")
        return classification_changes
    
    def create_high_confidence_subset(self, top_n: int = 1000) -> List[Dict]:
        """Create high-confidence subset for expert validation"""
        logger.info(f"Creating high-confidence subset of {top_n} samples...")
        
        # Score samples based on multiple factors
        scored_samples = []
        
        for sample in self.data:
            score = 0
            
            # Factor 1: Classification confidence
            if 'classification_confidence' in sample:
                score += sample['classification_confidence'] * 30
            elif sample['vulnerability_type'] != 'UNKNOWN':
                score += 20  # Known classification
            
            # Factor 2: Code complexity (moderate complexity is better)
            code_lines = len(sample['code'].split('\n'))
            if 10 <= code_lines <= 50:  # Sweet spot for review
                score += 15
            elif code_lines > 50:
                score += max(0, 15 - (code_lines - 50) * 0.1)
            
            # Factor 3: Presence of vulnerability indicators
            code_lower = sample['code'].lower()
            vuln_indicators = ['sql', 'query', 'user', 'input', 'param', 'exec', 'script', 'file']
            indicator_count = sum(1 for indicator in vuln_indicators if indicator in code_lower)
            score += min(indicator_count * 5, 25)
            
            # Factor 4: Diversity bonus (prefer different repositories)
            # This will be calculated after sorting
            
            scored_samples.append({
                'sample': sample,
                'score': score,
                'code_lines': code_lines,
                'vuln_indicators': indicator_count
            })
        
        # Sort by score
        scored_samples.sort(key=lambda x: x['score'], reverse=True)
        
        # Apply diversity selection
        selected_samples = []
        selected_repos = set()
        
        for scored_sample in scored_samples:
            if len(selected_samples) >= top_n:
                break
                
            sample = scored_sample['sample']
            repo = sample['repository']
            
            # Prefer samples from new repositories
            if repo not in selected_repos or len(selected_repos) > top_n * 0.8:
                selected_samples.append(sample)
                selected_repos.add(repo)
        
        logger.info(f"Selected {len(selected_samples)} high-confidence samples from {len(selected_repos)} repositories")
        return selected_samples
    
    def create_deduplication_strategy(self, exact_duplicates: Dict, semantic_duplicates: List) -> Dict:
        """Create strategy for handling duplicates"""
        deduplication_strategy = {
            'exact_duplicates': {
                'groups': len(exact_duplicates),
                'instances': sum(len(indices) for indices in exact_duplicates.values()),
                'keep_strategy': 'first_occurrence',
                'remove_indices': []
            },
            'semantic_duplicates': {
                'pairs': len(semantic_duplicates),
                'keep_strategy': 'higher_confidence',
                'remove_indices': []
            }
        }
        
        # Strategy for exact duplicates: keep first occurrence
        for hash_val, indices in exact_duplicates.items():
            # Keep first, remove others
            deduplication_strategy['exact_duplicates']['remove_indices'].extend(indices[1:])
        
        # Strategy for semantic duplicates: keep higher confidence
        processed_pairs = set()
        for i, j, similarity in semantic_duplicates:
            pair = tuple(sorted([i, j]))
            if pair in processed_pairs:
                continue
            processed_pairs.add(pair)
            
            sample_i = self.data[i]
            sample_j = self.data[j]
            
            # Decide which to keep based on confidence and quality
            score_i = sample_i.get('classification_confidence', 0)
            score_j = sample_j.get('classification_confidence', 0)
            
            if sample_i['vulnerability_type'] != 'UNKNOWN':
                score_i += 0.5
            if sample_j['vulnerability_type'] != 'UNKNOWN':
                score_j += 0.5
            
            # Remove the lower scoring one
            if score_i >= score_j:
                deduplication_strategy['semantic_duplicates']['remove_indices'].append(j)
            else:
                deduplication_strategy['semantic_duplicates']['remove_indices'].append(i)
        
        return deduplication_strategy
    
    def generate_expert_validation_report(self, 
                                        high_confidence_samples: List[Dict], 
                                        classification_changes: Dict,
                                        deduplication_strategy: Dict) -> None:
        """Generate comprehensive report for expert validation"""
        
        report_path = self.output_dir / 'expert_validation_report.md'
        
        with open(report_path, 'w') as f:
            f.write("# Expert Validation Report\n\n")
            f.write(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Dataset Overview
            f.write("## Dataset Overview\n\n")
            f.write(f"- **Total Samples**: {len(self.data):,}\n")
            f.write(f"- **Vulnerability Types**: {len(set(s['vulnerability_type'] for s in self.data))}\n")
            f.write(f"- **Unique Repositories**: {len(set(s['repository'] for s in self.data)):,}\n\n")
            
            # Vulnerability Distribution
            vuln_counts = Counter(s['vulnerability_type'] for s in self.data)
            f.write("### Vulnerability Type Distribution\n\n")
            for vuln_type, count in vuln_counts.most_common():
                pct = count / len(self.data) * 100
                f.write(f"- **{vuln_type}**: {count:,} samples ({pct:.1f}%)\n")
            f.write("\n")
            
            # Classification Enhancement Results
            f.write("## Classification Enhancement Results\n\n")
            f.write(f"- **Enhanced Samples**: {classification_changes['enhanced_count']:,}\n")
            f.write(f"- **Average Confidence**: {np.mean(classification_changes['confidence_scores']):.2f}\n\n")
            
            f.write("### Classification Changes\n\n")
            for change, count in classification_changes['changes_by_type'].items():
                f.write(f"- {change}: {count} samples\n")
            f.write("\n")
            
            # Deduplication Strategy
            f.write("## Deduplication Strategy\n\n")
            f.write("### Exact Duplicates\n")
            f.write(f"- **Groups**: {deduplication_strategy['exact_duplicates']['groups']}\n")
            f.write(f"- **Total Instances**: {deduplication_strategy['exact_duplicates']['instances']}\n")
            f.write(f"- **Samples to Remove**: {len(deduplication_strategy['exact_duplicates']['remove_indices'])}\n\n")
            
            f.write("### Semantic Duplicates\n")
            f.write(f"- **Similar Pairs**: {deduplication_strategy['semantic_duplicates']['pairs']}\n")
            f.write(f"- **Samples to Remove**: {len(deduplication_strategy['semantic_duplicates']['remove_indices'])}\n\n")
            
            # High-Confidence Samples
            f.write("## High-Confidence Samples for Expert Review\n\n")
            f.write(f"Selected **{len(high_confidence_samples)}** samples for expert validation based on:\n\n")
            f.write("1. Classification confidence scores\n")
            f.write("2. Code complexity (10-50 lines preferred)\n")
            f.write("3. Presence of vulnerability indicators\n")
            f.write("4. Repository diversity\n\n")
            
            # Sample examples
            f.write("### Sample Examples\n\n")
            for i, sample in enumerate(high_confidence_samples[:5]):
                f.write(f"#### Sample {i+1}\n")
                f.write(f"- **Type**: {sample['vulnerability_type']}\n")
                f.write(f"- **Repository**: {sample['repository']}\n")
                f.write(f"- **Confidence**: {sample.get('classification_confidence', 'N/A')}\n")
                f.write(f"- **Code Lines**: {len(sample['code'].split())}\n")
                f.write("```java\n")
                f.write(sample['code'][:200] + "...\n" if len(sample['code']) > 200 else sample['code'])
                f.write("```\n\n")
        
        logger.info(f"Expert validation report generated: {report_path}")
    
    def run_expert_validation_pipeline(self) -> Dict[str, Any]:
        """Run the complete expert validation pipeline"""
        logger.info("Starting Expert Validation Pipeline...")
        
        # Step 1: Detect exact duplicates
        exact_duplicates = self.detect_exact_duplicates()
        
        # Step 2: Enhance vulnerability classification
        classification_changes = self.enhance_vulnerability_classification()
        
        # Step 3: Detect semantic duplicates
        semantic_duplicates = self.detect_semantic_duplicates(similarity_threshold=0.85)
        
        # Step 4: Create deduplication strategy
        deduplication_strategy = self.create_deduplication_strategy(exact_duplicates, semantic_duplicates)
        
        # Step 5: Create high-confidence subset for expert validation
        high_confidence_samples = self.create_high_confidence_subset(top_n=1000)
        
        # Step 6: Generate expert validation report
        self.generate_expert_validation_report(
            high_confidence_samples, 
            classification_changes, 
            deduplication_strategy
        )
        
        # Step 7: Create clean dataset
        clean_dataset = self.create_clean_dataset(deduplication_strategy)
        
        # Step 8: Save results
        results = {
            'original_size': len(self.data),
            'clean_size': len(clean_dataset),
            'exact_duplicates_removed': len(deduplication_strategy['exact_duplicates']['remove_indices']),
            'semantic_duplicates_removed': len(deduplication_strategy['semantic_duplicates']['remove_indices']),
            'classification_enhanced': classification_changes['enhanced_count'],
            'high_confidence_samples': len(high_confidence_samples)
        }
        
        # Save clean dataset
        clean_dataset_path = self.output_dir / 'clean_dataset.json'
        with open(clean_dataset_path, 'w') as f:
            json.dump(clean_dataset, f, indent=2, default=str)
        
        # Save high-confidence samples for expert review
        expert_samples_path = self.output_dir / 'expert_validation_samples.json'
        with open(expert_samples_path, 'w') as f:
            json.dump(high_confidence_samples, f, indent=2, default=str)
        
        logger.info(f"Clean dataset saved: {clean_dataset_path}")
        logger.info(f"Expert samples saved: {expert_samples_path}")
        
        return results
    
    def create_clean_dataset(self, deduplication_strategy: Dict) -> List[Dict]:
        """Create clean dataset by removing duplicates"""
        all_remove_indices = set(
            deduplication_strategy['exact_duplicates']['remove_indices'] +
            deduplication_strategy['semantic_duplicates']['remove_indices']
        )
        
        clean_dataset = [
            sample for i, sample in enumerate(self.data)
            if i not in all_remove_indices
        ]
        
        logger.info(f"Clean dataset: {len(clean_dataset)} samples (removed {len(all_remove_indices)} duplicates)")
        return clean_dataset


def main():
    """Main execution function"""
    dataset_path = "Dataset/complete_wartschinski_final/complete_wartschinski_all_formats.json"
    
    # Initialize pipeline
    pipeline = ExpertValidationPipeline(dataset_path)
    
    # Run pipeline
    results = pipeline.run_expert_validation_pipeline()
    
    # Print summary
    print("\n" + "="*60)
    print("EXPERT VALIDATION PIPELINE RESULTS")
    print("="*60)
    
    print(f"\nDataset Improvement:")
    print(f"  Original samples: {results['original_size']:,}")
    print(f"  Clean samples: {results['clean_size']:,}")
    print(f"  Improvement: {((results['original_size'] - results['clean_size']) / results['original_size'] * 100):.1f}% duplicates removed")
    
    print(f"\nDeduplication Results:")
    print(f"  Exact duplicates removed: {results['exact_duplicates_removed']:,}")
    print(f"  Semantic duplicates removed: {results['semantic_duplicates_removed']:,}")
    
    print(f"\nClassification Enhancement:")
    print(f"  Samples with improved classification: {results['classification_enhanced']:,}")
    
    print(f"\nExpert Validation:")
    print(f"  High-confidence samples selected: {results['high_confidence_samples']:,}")
    
    print(f"\nFiles Generated:")
    print(f"  clean_dataset.json - {results['clean_size']:,} deduplicated samples")
    print(f"  expert_validation_samples.json - {results['high_confidence_samples']:,} samples for review")
    print(f"  expert_validation_report.md - Comprehensive analysis report")
    
    print("="*60)


if __name__ == "__main__":
    main()