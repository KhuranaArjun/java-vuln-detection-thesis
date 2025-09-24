#!/usr/bin/env python3
"""
Complete Java Vulnerability Dataset Generation Pipeline
Based on Laura Wartschinski's VUDENC methodology

This script runs the complete pipeline and can also run individual steps.
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
import subprocess

# Configure logging
def setup_logging(log_level='INFO'):
    """Setup logging configuration"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        level=getattr(logging, log_level),
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(f'pipeline_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        ]
    )

logger = logging.getLogger(__name__)

class JavaVulnerabilityPipeline:
    """Complete pipeline for Java vulnerability dataset generation"""
    
    def __init__(self, config: dict):
        self.config = config
        self.github_token = None
        self.setup_directories()
        self.load_github_token()
    
    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            'data', 'models', 'logs', 'results', 
            'java_corpus', 'training_data'
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            logger.info(f"Created directory: {directory}")
    
    def load_github_token(self):
        """Load GitHub API token"""
        token_file = self.config.get('github_token_file', 'github_token.txt')
        
        if os.path.exists(token_file):
            with open(token_file, 'r') as f:
                self.github_token = f.read().strip()
            logger.info("GitHub token loaded successfully")
        else:
            logger.error(f"GitHub token file not found: {token_file}")
            logger.error("Please create a GitHub personal access token:")
            logger.error("1. Visit: https://github.com/settings/tokens")
            logger.error("2. Create token with 'public_repo' scope")
            logger.error(f"3. Save token to: {token_file}")
            return False
        return True
    
    def run_step1_scraping(self):
        """Step 1: Scrape vulnerability commits from GitHub"""
        logger.info("="*60)
        logger.info("STEP 1: GITHUB VULNERABILITY COMMIT SCRAPING")
        logger.info("="*60)
        
        if not self.load_github_token():
            return None
            
        try:
            from java_vulnerability_scraper import JavaVulnerabilityCommitScraper
            
            scraper = JavaVulnerabilityCommitScraper(self.github_token)
            
            output_file = 'java_vulnerability_commits.json'
            
            commits = scraper.run_scraping_pipeline(
                output_file=output_file,
                max_repos=self.config.get('max_repos', 50),
                max_commits_per_repo=self.config.get('max_commits_per_repo', 30)
            )
            
            logger.info(f"Step 1 complete: {len(commits)} commits collected")
            return output_file
            
        except ImportError:
            logger.error("java_vulnerability_scraper.py not found. Please ensure all scripts are in the same directory.")
            return None
        except Exception as e:
            logger.error(f"Step 1 failed: {e}")
            return None
    
    def run_step2_processing(self, commits_file: str):
        """Step 2: Process commits and create labeled dataset"""
        logger.info("="*60)
        logger.info("STEP 2: DATASET PROCESSING & LABELING")
        logger.info("="*60)
        
        try:
            from java_dataset_processor import JavaDatasetProcessor
            
            processor = JavaDatasetProcessor(
                context_window=self.config.get('context_window', 10)
            )
            
            output_file = 'java_vulnerability_dataset.json'
            
            samples = processor.process_commits_dataset(
                commits_file=commits_file,
                output_file=output_file,
                max_samples_per_commit=self.config.get('max_samples_per_commit', 30)
            )
            
            logger.info(f"Step 2 complete: {len(samples)} training samples created")
            return output_file
            
        except ImportError:
            logger.error("java_dataset_processor.py not found. Please ensure all scripts are in the same directory.")
            return None
        except Exception as e:
            logger.error(f"Step 2 failed: {e}")
            return None
    
    def run_step3_word2vec(self, dataset_file: str):
        """Step 3: Train Word2Vec and vectorize dataset"""
        logger.info("="*60)
        logger.info("STEP 3: WORD2VEC TRAINING & VECTORIZATION")
        logger.info("="*60)
        
        try:
            from java_word2vec_trainer import JavaWord2VecTrainer
            
            trainer = JavaWord2VecTrainer(
                vector_size=self.config.get('vector_size', 200),
                window=self.config.get('word2vec_window', 10),
                min_count=self.config.get('min_count', 5),
                workers=self.config.get('workers', 4)
            )
            
            # Step 3a: Create/download Java corpus
            corpus_file = trainer.create_java_corpus_from_existing_data(dataset_file)
            
            # Step 3b: Train Word2Vec model
            model_file = 'java_word2vec.model'
            model = trainer.train_word2vec_model(corpus_file, model_file)
            
            # Step 3c: Vectorize vulnerability dataset
            vectorized_file = 'vectorized_dataset.pkl'
            vectorized_data = trainer.vectorize_dataset(dataset_file, vectorized_file)
            
            # Step 3d: Prepare training data splits
            training_data = trainer.prepare_training_data(
                vectorized_file=vectorized_file,
                test_size=self.config.get('test_size', 0.2),
                val_size=self.config.get('val_size', 0.1),
                output_dir='training_data'
            )
            
            logger.info("Step 3 complete: Training data prepared")
            return training_data
            
        except ImportError:
            logger.error("java_word2vec_trainer.py not found. Please ensure all scripts are in the same directory.")
            return None
        except Exception as e:
            logger.error(f"Step 3 failed: {e}")
            return None
    
    def generate_report(self, training_data: dict):
        """Generate final pipeline report"""
        logger.info("="*60)
        logger.info("PIPELINE COMPLETION REPORT")
        logger.info("="*60)
        
        report = {
            'pipeline_config': self.config,
            'execution_timestamp': datetime.now().isoformat(),
            'training_data_info': training_data['data_info'] if training_data else {},
            'files_created': {
                'commits_data': 'java_vulnerability_commits.json',
                'labeled_dataset': 'java_vulnerability_dataset.json',
                'word2vec_model': 'java_word2vec.model',
                'vectorized_data': 'vectorized_dataset.pkl',
                'training_splits': 'training_data/*.npy'
            },
            'next_steps': [
                'Train LSTM model using training_data/',
                'Evaluate model performance on test set',
                'Fine-tune hyperparameters based on validation results',
                'Deploy model for vulnerability detection'
            ]
        }
        
        # Save report
        os.makedirs('results', exist_ok=True)
        report_file = f'results/pipeline_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        logger.info("🎉 PIPELINE SUCCESSFULLY COMPLETED!")
        if training_data:
            logger.info(f"📊 Training samples: {training_data['data_info']['train_samples']}")
            logger.info(f"📊 Validation samples: {training_data['data_info']['val_samples']}")
            logger.info(f"📊 Test samples: {training_data['data_info']['test_samples']}")
            logger.info(f"📊 Max sequence length: {training_data['data_info']['max_sequence_length']}")
            logger.info(f"📊 Vector dimension: {training_data['data_info']['vector_size']}")
            logger.info(f"📊 Vocabulary size: {training_data['data_info']['vocabulary_size']}")
        logger.info(f"📋 Report saved to: {report_file}")
        
        return report_file
    
    def run_complete_pipeline(self):
        """Run the complete pipeline"""
        try:
            logger.info("🚀 Starting Java Vulnerability Dataset Generation Pipeline")
            logger.info("Based on Laura Wartschinski's VUDENC methodology")
            logger.info(f"Configuration: {self.config}")
            
            # Step 1: Scrape vulnerability commits
            commits_file = self.run_step1_scraping()
            if not commits_file:
                raise Exception("Step 1 (scraping) failed")
            
            # Step 2: Process and label dataset
            dataset_file = self.run_step2_processing(commits_file)
            if not dataset_file:
                raise Exception("Step 2 (processing) failed")
            
            # Step 3: Train Word2Vec and prepare training data
            training_data = self.run_step3_word2vec(dataset_file)
            if not training_data:
                raise Exception("Step 3 (word2vec) failed")
            
            # Generate final report
            report_file = self.generate_report(training_data)
            
            logger.info("✅ Pipeline completed successfully!")
            return report_file
            
        except Exception as e:
            logger.error(f"❌ Pipeline failed: {e}")
            logger.exception("Full error traceback:")
            raise
    
    def run_individual_step(self, step_number: int):
        """Run an individual pipeline step"""
        if step_number == 1:
            return self.run_step1_scraping()
        elif step_number == 2:
            commits_file = 'java_vulnerability_commits.json'
            if not os.path.exists(commits_file):
                logger.error(f"Required file not found: {commits_file}")
                logger.error("Please run step 1 first or provide the commits file")
                return None
            return self.run_step2_processing(commits_file)
        elif step_number == 3:
            dataset_file = 'java_vulnerability_dataset.json'
            if not os.path.exists(dataset_file):
                logger.error(f"Required file not found: {dataset_file}")
                logger.error("Please run steps 1-2 first or provide the dataset file")
                return None
            return self.run_step3_word2vec(dataset_file)
        else:
            logger.error(f"Invalid step number: {step_number}. Valid steps are 1, 2, or 3")
            return None

def create_default_config():
    """Create default pipeline configuration"""
    return {
        # GitHub scraping
        'github_token_file': 'github_token.txt',
        'max_repos': 50,
        'max_commits_per_repo': 30,
        
        # Dataset processing
        'context_window': 10,
        'max_samples_per_commit': 30,
        
        # Word2Vec training
        'vector_size': 200,
        'word2vec_window': 10,
        'min_count': 5,
        'workers': 4,
        
        # Data splitting
        'test_size': 0.2,
        'val_size': 0.1
    }

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description="Java Vulnerability Dataset Generation Pipeline"
    )
    parser.add_argument(
        '--config', 
        type=str, 
        help='JSON configuration file path'
    )
    parser.add_argument(
        '--log-level', 
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level'
    )
    parser.add_argument(
        '--step',
        type=int,
        choices=[1, 2, 3],
        help='Run only a specific step (1=scraping, 2=processing, 3=word2vec)'
    )
    parser.add_argument(
        '--quick-test',
        action='store_true',
        help='Run with reduced parameters for quick testing'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Load configuration
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
        logger.info(f"Loaded configuration from: {args.config}")
    else:
        config = create_default_config()
        logger.info("Using default configuration")
    
    # Quick test mode
    if args.quick_test:
        logger.info("Running in quick test mode")
        config.update({
            'max_repos': 5,
            'max_commits_per_repo': 10,
            'max_samples_per_commit': 10
        })
    
    # Save configuration
    os.makedirs('results', exist_ok=True)
    config_file = 'results/pipeline_config.json'
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    logger.info(f"Configuration saved to: {config_file}")
    
    # Run pipeline
    pipeline = JavaVulnerabilityPipeline(config)
    
    if args.step:
        # Run individual step
        logger.info(f"Running step {args.step} only")
        result = pipeline.run_individual_step(args.step)
        if result:
            logger.info(f"Step {args.step} completed successfully")
        else:
            logger.error(f"Step {args.step} failed")
            sys.exit(1)
    else:
        # Run complete pipeline
        report_file = pipeline.run_complete_pipeline()
        
        print("\n" + "="*60)
        print("🎉 JAVA VULNERABILITY DATASET GENERATION COMPLETE!")
        print("="*60)
        print(f"📋 Report: {report_file}")
        print("📁 Training data: training_data/")
        print("🤖 Ready for LSTM model training!")
        print("="*60)

if __name__ == "__main__":
    main()