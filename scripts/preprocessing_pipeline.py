#!/usr/bin/env python3
"""
Large Dataset Preprocessor - Memory Efficient
Handles 2.6M sample dataset efficiently for top 6 vulnerability classes
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging
from datetime import datetime
from collections import Counter
import re

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LargeDatasetPreprocessor:
    def __init__(self, project_dir: str = "~/java-vulnerability-detection-backup"):
        self.project_dir = Path(project_dir).expanduser()
        self.output_dir = self.project_dir / "processed"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Top 6 vulnerability classes to focus on
        self.target_classes = {
            'COMMAND_INJECTION',
            'PATH_TRAVERSAL', 
            'CSRF',
            'XSS',
            'SQL_INJECTION',
            'BROKEN_AUTHENTICATION'
        }
        
        # Map alternative class names to standard names
        self.class_mapping = {
            'command_injection': 'COMMAND_INJECTION',
            'path_traversal': 'PATH_TRAVERSAL',
            'csrf': 'CSRF',
            'xss': 'XSS',
            'cross_site_scripting': 'XSS',
            'sql_injection': 'SQL_INJECTION',
            'sqli': 'SQL_INJECTION',
            'broken_authentication': 'BROKEN_AUTHENTICATION',
            'authentication': 'BROKEN_AUTHENTICATION',
            'access_control': 'BROKEN_ACCESS_CONTROL',
            'broken_access_control': 'BROKEN_ACCESS_CONTROL',
            'xxe': 'XXE',
            'deserialization': 'INSECURE_DESERIALIZATION',
            'insecure_deserialization': 'INSECURE_DESERIALIZATION'
        }
        
        # Target samples per class for balanced dataset
        self.target_samples_per_class = 15000
    
    def analyze_large_dataset(self, file_path: str):
        """Analyze the large dataset efficiently"""
        
        logger.info(f"Analyzing large dataset: {file_path}")
        
        # Read in chunks to avoid memory issues
        chunk_size = 10000
        class_counter = Counter()
        total_rows = 0
        
        logger.info("Reading dataset in chunks to analyze class distribution...")
        
        for chunk in pd.read_csv(file_path, chunksize=chunk_size):
            total_rows += len(chunk)
            
            if 'vulnerability_class' in chunk.columns:
                # Normalize class names
                chunk['vulnerability_class'] = chunk['vulnerability_class'].str.lower().str.strip()
                class_counter.update(chunk['vulnerability_class'].value_counts().to_dict())
            
            # Progress update
            if total_rows % 100000 == 0:
                logger.info(f"Processed {total_rows:,} rows...")
        
        logger.info(f"✅ Analysis complete: {total_rows:,} total samples")
        
        # Show class distribution
        logger.info("Top 20 vulnerability classes found:")
        for class_name, count in class_counter.most_common(20):
            logger.info(f"  {class_name}: {count:,}")
        
        return total_rows, class_counter
    
    def normalize_class_name(self, class_name: str) -> str:
        """Normalize vulnerability class names"""
        
        if pd.isna(class_name):
            return 'OTHER'
        
        class_name = str(class_name).lower().strip()
        
        # Direct mapping
        if class_name in self.class_mapping:
            return self.class_mapping[class_name]
        
        # Partial matching
        for pattern, target in self.class_mapping.items():
            if pattern in class_name:
                return target
        
        # Check if it's already in target format
        class_upper = class_name.upper()
        if class_upper in self.target_classes:
            return class_upper
        
        return 'OTHER'
    
    def sample_top_classes_efficiently(self, file_path: str, target_classes: set, samples_per_class: int = 15000):
        """Sample top classes efficiently from large dataset"""
        
        logger.info(f"Sampling {samples_per_class:,} samples per class for: {target_classes}")
        
        # Initialize collectors for each target class
        class_samples = {class_name: [] for class_name in target_classes}
        class_counts = {class_name: 0 for class_name in target_classes}
        
        chunk_size = 10000
        total_processed = 0
        
        for chunk in pd.read_csv(file_path, chunksize=chunk_size):
            total_processed += len(chunk)
            
            # Normalize class names
            chunk['normalized_class'] = chunk['vulnerability_class'].apply(self.normalize_class_name)
            
            # Sample from each target class
            for target_class in target_classes:
                if class_counts[target_class] >= samples_per_class:
                    continue  # Already have enough samples
                
                # Get samples for this class
                class_chunk = chunk[chunk['normalized_class'] == target_class]
                
                if len(class_chunk) > 0:
                    # Take samples up to our limit
                    needed = samples_per_class - class_counts[target_class]
                    take = min(len(class_chunk), needed)
                    
                    if take > 0:
                        sampled = class_chunk.head(take).copy()
                        sampled['vulnerability_type'] = target_class
                        class_samples[target_class].append(sampled)
                        class_counts[target_class] += take
                        
                        logger.info(f"{target_class}: {class_counts[target_class]:,}/{samples_per_class:,} samples")
            
            # Progress update
            if total_processed % 100000 == 0:
                logger.info(f"Processed {total_processed:,} rows...")
                
                # Check if we have enough samples for all classes
                if all(count >= samples_per_class for count in class_counts.values()):
                    logger.info("✅ Collected enough samples for all target classes!")
                    break
        
        # Combine all samples
        logger.info("Combining sampled data...")
        all_samples = []
        
        for class_name, sample_list in class_samples.items():
            if sample_list:
                class_df = pd.concat(sample_list, ignore_index=True)
                all_samples.append(class_df)
                logger.info(f"✅ {class_name}: {len(class_df):,} samples collected")
            else:
                logger.warning(f"⚠️  {class_name}: No samples found")
        
        if all_samples:
            final_df = pd.concat(all_samples, ignore_index=True)
            logger.info(f"✅ Total sampled dataset: {len(final_df):,} samples")
            return final_df
        else:
            logger.error("❌ No samples collected!")
            return pd.DataFrame()
    
    def add_new_collections(self, sampled_df: pd.DataFrame) -> pd.DataFrame:
        """Add the new collections (GitHub, NVD, JIRA) to sampled data"""
        
        logger.info("Adding new vulnerability collections...")
        
        datasets_to_add = []
        
        # GitHub Advisories
        github_file = self.project_dir / "datasets/raw/github_advisories/github_advisories_20250907_220100.csv"
        if github_file.exists():
            try:
                github_df = pd.read_csv(github_file)
                github_df['content'] = github_df['description'].fillna('')
                github_df['vulnerability_type'] = 'XSS'  # All GitHub samples were XSS
                github_df['source'] = 'github_advisories'
                datasets_to_add.append(github_df[['content', 'vulnerability_type', 'source']])
                logger.info(f"✅ Added GitHub Advisories: {len(github_df):,} samples")
            except Exception as e:
                logger.warning(f"Failed to load GitHub data: {e}")
        
        # NVD
        nvd_file = self.project_dir / "datasets/raw/nvd/nvd_java_vulnerabilities_20250908_003357.csv"
        if nvd_file.exists():
            try:
                nvd_df = pd.read_csv(nvd_file)
                nvd_df['content'] = nvd_df['description'].fillna('')
                nvd_df['source'] = 'nvd'
                datasets_to_add.append(nvd_df[['content', 'vulnerability_type', 'source']])
                logger.info(f"✅ Added NVD: {len(nvd_df):,} samples")
            except Exception as e:
                logger.warning(f"Failed to load NVD data: {e}")
        
        # Apache JIRA
        jira_file = self.project_dir / "datasets/raw/apache_jira/apache_jira_vulnerabilities_20250907.csv"
        if jira_file.exists():
            try:
                jira_df = pd.read_csv(jira_file)
                jira_df['content'] = jira_df['description'].fillna('')
                jira_df['source'] = 'apache_jira'
                datasets_to_add.append(jira_df[['content', 'vulnerability_type', 'source']])
                logger.info(f"✅ Added Apache JIRA: {len(jira_df):,} samples")
            except Exception as e:
                logger.warning(f"Failed to load JIRA data: {e}")
        
        # Add original dataset source
        sampled_df['source'] = 'original_dataset'
        
        # Combine all datasets
        if datasets_to_add:
            all_datasets = [sampled_df[['content', 'vulnerability_type', 'source']]] + datasets_to_add
            combined_df = pd.concat(all_datasets, ignore_index=True)
            logger.info(f"✅ Combined dataset: {len(combined_df):,} total samples")
            return combined_df
        else:
            return sampled_df[['content', 'vulnerability_type', 'source']]
    
    def clean_and_prepare_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and prepare the final dataset"""
        
        logger.info("Cleaning and preparing dataset...")
        
        # Remove samples with insufficient content
        initial_count = len(df)
        df = df[df['content'].str.len() > 50].copy()
        logger.info(f"After content length filter: {len(df):,} samples (removed {initial_count - len(df):,})")
        
        # Normalize vulnerability types to target classes
        df['vulnerability_type'] = df['vulnerability_type'].apply(self.normalize_class_name)
        
        # Filter to target classes only
        df = df[df['vulnerability_type'].isin(self.target_classes)].copy()
        logger.info(f"After target class filter: {len(df):,} samples")
        
        # Remove duplicates based on content
        df = df.drop_duplicates(subset=['content'], keep='first')
        logger.info(f"After deduplication: {len(df):,} samples")
        
        # Balance classes to maximum target
        balanced_dfs = []
        for class_name in self.target_classes:
            class_df = df[df['vulnerability_type'] == class_name].copy()
            
            if len(class_df) > self.target_samples_per_class:
                class_df = class_df.sample(n=self.target_samples_per_class, random_state=42)
                logger.info(f"{class_name}: Reduced to {self.target_samples_per_class:,} samples")
            else:
                logger.info(f"{class_name}: Keeping all {len(class_df):,} samples")
            
            if len(class_df) > 0:
                balanced_dfs.append(class_df)
        
        # Combine balanced classes
        if balanced_dfs:
            final_df = pd.concat(balanced_dfs, ignore_index=True)
            final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
            logger.info(f"✅ Final balanced dataset: {len(final_df):,} samples")
            return final_df
        else:
            logger.error("❌ No balanced data created!")
            return pd.DataFrame()
    
    def save_final_dataset(self, df: pd.DataFrame) -> str:
        """Save the final processed dataset"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save main dataset
        output_file = self.output_dir / f"java_vulnerabilities_balanced_top6_{timestamp}.csv"
        df.to_csv(output_file, index=False)
        logger.info(f"✅ Saved balanced dataset: {output_file}")
        
        # Save summary
        summary_file = self.output_dir / f"dataset_summary_{timestamp}.txt"
        with open(summary_file, 'w') as f:
            f.write("Java Vulnerability Dataset - Top 6 Classes\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Processing Date: {datetime.now().isoformat()}\n")
            f.write(f"Total Samples: {len(df):,}\n\n")
            
            f.write("Class Distribution:\n")
            f.write("-" * 30 + "\n")
            class_counts = df['vulnerability_type'].value_counts()
            for class_name, count in class_counts.items():
                percentage = (count / len(df)) * 100
                f.write(f"{class_name:25}: {count:6,} ({percentage:5.1f}%)\n")
            
            f.write(f"\nData Sources:\n")
            f.write("-" * 30 + "\n")
            source_counts = df['source'].value_counts()
            for source, count in source_counts.items():
                percentage = (count / len(df)) * 100
                f.write(f"{source:20}: {count:6,} ({percentage:5.1f}%)\n")
        
        logger.info(f"✅ Saved summary: {summary_file}")
        
        return str(output_file)
    
    def run_large_dataset_pipeline(self):
        """Run the complete pipeline for large dataset"""
        
        logger.info("🚀 Starting Large Dataset Preprocessing Pipeline")
        
        # Large dataset path
        large_dataset = "/Users/ARJUN/java-vulnerability-detection-backup/datasets/processed/comprehensive_classified_ALL_java_vulnerabilities_20250907_123556.csv"
        
        # Step 1: Analyze the large dataset
        total_rows, class_distribution = self.analyze_large_dataset(large_dataset)
        
        # Step 2: Sample top 6 classes efficiently
        sampled_df = self.sample_top_classes_efficiently(
            large_dataset, 
            self.target_classes, 
            self.target_samples_per_class
        )
        
        if sampled_df.empty:
            logger.error("❌ No data sampled from large dataset!")
            return
        
        # Step 3: Add new collections
        combined_df = self.add_new_collections(sampled_df)
        
        # Step 4: Clean and prepare final dataset
        final_df = self.clean_and_prepare_dataset(combined_df)
        
        # Step 5: Save results
        output_file = self.save_final_dataset(final_df)
        
        # Step 6: Print summary
        print("\n" + "="*70)
        print("🎉 LARGE DATASET PREPROCESSING COMPLETE")
        print("="*70)
        
        if not final_df.empty:
            class_counts = final_df['vulnerability_type'].value_counts()
            print(f"Final dataset: {len(final_df):,} samples across {len(class_counts)} classes")
            print("\nClass distribution:")
            for class_name, count in class_counts.items():
                percentage = (count / len(final_df)) * 100
                print(f"  {class_name:25}: {count:6,} ({percentage:5.1f}%)")
            
            print(f"\n✅ Dataset ready for ML training: {output_file}")
        else:
            print("❌ No final dataset created!")
        
        return output_file

def main():
    """Main execution function"""
    
    preprocessor = LargeDatasetPreprocessor()
    
    try:
        output_file = preprocessor.run_large_dataset_pipeline()
        if output_file:
            print(f"\n🎯 SUCCESS: Large dataset preprocessing complete!")
            print(f"📁 Ready for model training: {output_file}")
        else:
            print("❌ Preprocessing failed!")
            
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        raise

if __name__ == "__main__":
    main()