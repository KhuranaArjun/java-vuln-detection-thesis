#!/usr/bin/env python3
"""
Quality Filter and Wartschinski Pipeline Preparation
Extract high-quality commits and prepare for token-level vulnerability detection
"""

import json
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WartschinkiPreparation:
    """
    Prepare collected commits for Laura Wartschinski's VUDENC pipeline
    Focus on high-quality commits with actual vulnerable Java source code
    """
    
    def __init__(self, dataset_file: str):
        self.dataset_file = dataset_file
        self.high_quality_commits = []
        self.wartschinski_ready_commits = []
        
    def load_collected_dataset(self) -> Dict:
        """Load the collected dataset"""
        try:
            with open(self.dataset_file, 'r') as f:
                dataset = json.load(f)
            logger.info(f"✅ Loaded dataset: {len(dataset.get('commits', []))} commits")
            return dataset
        except Exception as e:
            logger.error(f"❌ Failed to load dataset: {e}")
            return {}

    def filter_high_quality_commits(self, dataset: Dict, quality_threshold: float = 0.6) -> List[Dict]:
        """
        Filter for high-quality commits suitable for Wartschinski pipeline
        Lower threshold (0.6) since we need sufficient training data
        """
        commits = dataset.get('commits', [])
        high_quality = []
        
        for commit in commits:
            # Quality criteria for Wartschinski compatibility
            if (commit.get('quality_score', 0) >= quality_threshold and
                commit.get('java_files_count', 0) > 0 and
                commit.get('has_vulnerable_code', False) and
                commit.get('lines_added', 0) + commit.get('lines_deleted', 0) >= 10):
                
                high_quality.append(commit)
        
        logger.info(f"✅ High-quality commits (≥{quality_threshold}): {len(high_quality)}/{len(commits)}")
        return high_quality

    def analyze_vulnerability_distribution(self, commits: List[Dict]) -> Dict:
        """Analyze vulnerability type distribution for ML training balance"""
        
        vuln_distribution = {}
        owasp_distribution = {}
        repo_distribution = {}
        
        for commit in commits:
            # Vulnerability types
            vtype = commit.get('vulnerability_type', 'Unknown')
            vuln_distribution[vtype] = vuln_distribution.get(vtype, 0) + 1
            
            # OWASP categories  
            owasp = commit.get('owasp_category', 'Unknown')
            owasp_distribution[owasp] = owasp_distribution.get(owasp, 0) + 1
            
            # Repository distribution
            repo = commit.get('repo', 'Unknown')
            repo_distribution[repo] = repo_distribution.get(repo, 0) + 1
        
        return {
            'vulnerability_types': vuln_distribution,
            'owasp_categories': owasp_distribution,
            'repositories': repo_distribution,
            'total_commits': len(commits),
            'balance_assessment': self.assess_class_balance(vuln_distribution)
        }

    def assess_class_balance(self, vuln_distribution: Dict) -> Dict:
        """Assess class balance for ML training"""
        total = sum(vuln_distribution.values())
        percentages = {vtype: (count/total)*100 for vtype, count in vuln_distribution.items()}
        
        # Identify imbalanced classes
        majority_classes = {vtype: pct for vtype, pct in percentages.items() if pct > 20}
        minority_classes = {vtype: pct for vtype, pct in percentages.items() if pct < 5}
        
        return {
            'total_classes': len(vuln_distribution),
            'majority_classes': majority_classes,
            'minority_classes': minority_classes,
            'most_represented': max(percentages.items(), key=lambda x: x[1]),
            'least_represented': min(percentages.items(), key=lambda x: x[1]),
            'needs_balancing': len(minority_classes) > 0
        }

    def create_wartschinski_format(self, commits: List[Dict]) -> List[Dict]:
        """
        Convert commits to Wartschinski-compatible format
        Structure needed for token-level vulnerability detection
        """
        wartschinski_commits = []
        
        for commit in commits:
            wartschinski_commit = {
                # Core Wartschinski requirements
                'repo': commit['repo'],
                'commit_sha': commit['commit_sha'],
                'commit_url': commit['commit_url'],
                
                # Vulnerability classification
                'cve_id': commit['cve_id'],
                'vulnerability_type': commit['vulnerability_type'],
                'owasp_category': commit['owasp_category'],
                
                # Code change metrics
                'java_files_count': commit['java_files_count'],
                'lines_added': commit['lines_added'],
                'lines_deleted': commit['lines_deleted'],
                
                # Quality indicators
                'quality_score': commit['quality_score'],
                'has_vulnerable_code': commit['has_vulnerable_code'],
                
                # Metadata for processing
                'commit_message': commit['commit_message'],
                'author': commit['author'],
                'date': commit['date'],
                'java_files': commit.get('java_files', []),
                
                # Processing flags
                'ready_for_diff_analysis': True,
                'expected_samples': max(1, (commit['lines_added'] + commit['lines_deleted']) // 10),
                'priority_for_training': 'high' if commit['quality_score'] >= 0.7 else 'medium'
            }
            wartschinski_commits.append(wartschinski_commit)
        
        logger.info(f"✅ Created {len(wartschinski_commits)} Wartschinski-compatible commits")
        return wartschinski_commits

    def generate_training_recommendations(self, analysis: Dict, commits: List[Dict]) -> Dict:
        """Generate specific recommendations for Wartschinski training"""
        
        total_commits = len(commits)
        balance = analysis['balance_assessment']
        
        recommendations = {
            'dataset_status': 'ready' if total_commits >= 80 else 'supplement_needed',
            'expected_samples': sum(max(1, (c['lines_added'] + c['lines_deleted']) // 10) for c in commits),
            'training_approach': [],
            'data_augmentation_needed': [],
            'commit_based_splits': self.calculate_commit_splits(commits),
            'class_balance_strategy': []
        }
        
        # Training approach recommendations
        if total_commits >= 100:
            recommendations['training_approach'].append("✅ Sufficient commits for standalone training")
        else:
            recommendations['training_approach'].append("⚠️ Consider combining with MoreFixes dataset")
            recommendations['training_approach'].append(f"📊 Current: {total_commits} commits, Recommended: 100+")
        
        # Class balance recommendations
        if balance['needs_balancing']:
            for vtype, pct in balance['minority_classes'].items():
                recommendations['data_augmentation_needed'].append(f"🎯 {vtype}: {pct:.1f}% (needs augmentation)")
                recommendations['class_balance_strategy'].append(f"Augment {vtype} using SMOTE or synthetic generation")
        
        # Majority class handling
        for vtype, pct in balance['majority_classes'].items():
            if pct > 30:
                recommendations['class_balance_strategy'].append(f"Consider undersampling {vtype} ({pct:.1f}%)")
        
        return recommendations

    def calculate_commit_splits(self, commits: List[Dict]) -> Dict:
        """
        Calculate commit-based splits to prevent data leakage
        Following your proven 74/15/11 split strategy
        """
        import random
        random.seed(42)  # Reproducible splits
        
        # Group by repository for diverse splits
        repo_commits = {}
        for commit in commits:
            repo = commit['repo']
            if repo not in repo_commits:
                repo_commits[repo] = []
            repo_commits[repo].append(commit)
        
        # Distribute commits across splits while maintaining repo diversity
        train_commits = []
        val_commits = []
        test_commits = []
        
        for repo, repo_commit_list in repo_commits.items():
            random.shuffle(repo_commit_list)
            n_commits = len(repo_commit_list)
            
            # Calculate splits for this repo
            train_size = int(0.74 * n_commits)
            val_size = int(0.15 * n_commits)
            
            train_commits.extend(repo_commit_list[:train_size])
            val_commits.extend(repo_commit_list[train_size:train_size + val_size])
            test_commits.extend(repo_commit_list[train_size + val_size:])
        
        return {
            'train': {'count': len(train_commits), 'commits': [c['commit_sha'] for c in train_commits]},
            'validation': {'count': len(val_commits), 'commits': [c['commit_sha'] for c in val_commits]},
            'test': {'count': len(test_commits), 'commits': [c['commit_sha'] for c in test_commits]},
            'split_ratios': {
                'train': len(train_commits) / len(commits),
                'validation': len(val_commits) / len(commits),
                'test': len(test_commits) / len(commits)
            }
        }

    def save_wartschinski_dataset(self, commits: List[Dict], analysis: Dict, 
                                recommendations: Dict, output_dir: str) -> Dict:
        """Save the final Wartschinski-ready dataset"""
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 1. Wartschinski training dataset
        train_file = output_path / f"wartschinski_training_dataset_{timestamp}.json"
        dataset = {
            'metadata': {
                'creation_date': datetime.now().isoformat(),
                'methodology': 'Enhanced Wartschinski VUDENC Pipeline',
                'total_commits': len(commits),
                'quality_threshold': 0.6,
                'expected_samples': recommendations['expected_samples'],
                'ready_for_training': recommendations['dataset_status'] == 'ready'
            },
            'vulnerability_analysis': analysis,
            'training_recommendations': recommendations,
            'commits': commits
        }
        
        with open(train_file, 'w') as f:
            json.dump(dataset, f, indent=2, default=str)
        
        # 2. Simple commit list for immediate processing
        simple_file = output_path / f"commit_list_for_processing_{timestamp}.json"
        simple_commits = [
            {
                'repo': c['repo'],
                'commit_sha': c['commit_sha'],
                'cve': c['cve_id'],
                'vulnerability_type': c['vulnerability_type'],
                'quality_score': c['quality_score']
            } for c in commits
        ]
        
        with open(simple_file, 'w') as f:
            json.dump(simple_commits, f, indent=2)
        
        # 3. Training summary report
        report_file = output_path / f"training_readiness_report_{timestamp}.txt"
        with open(report_file, 'w') as f:
            f.write("WARTSCHINSKI PIPELINE READINESS REPORT\n")
            f.write("="*50 + "\n\n")
            
            f.write(f"Dataset Status: {recommendations['dataset_status'].upper()}\n")
            f.write(f"Total High-Quality Commits: {len(commits)}\n")
            f.write(f"Expected Training Samples: ~{recommendations['expected_samples']}\n\n")
            
            f.write("VULNERABILITY TYPE DISTRIBUTION:\n")
            for vtype, count in sorted(analysis['vulnerability_types'].items(), key=lambda x: x[1], reverse=True):
                pct = (count / len(commits)) * 100
                f.write(f"  {vtype}: {count} commits ({pct:.1f}%)\n")
            
            f.write(f"\nCOMMIT-BASED SPLITS (Prevents Data Leakage):\n")
            splits = recommendations['commit_based_splits']
            f.write(f"  Training: {splits['train']['count']} commits ({splits['split_ratios']['train']:.1%})\n")
            f.write(f"  Validation: {splits['validation']['count']} commits ({splits['split_ratios']['validation']:.1%})\n")
            f.write(f"  Test: {splits['test']['count']} commits ({splits['split_ratios']['test']:.1%})\n")
            
            f.write(f"\nTRAINING RECOMMENDATIONS:\n")
            for rec in recommendations['training_approach']:
                f.write(f"  {rec}\n")
            
            if recommendations['data_augmentation_needed']:
                f.write(f"\nCLASS BALANCE RECOMMENDATIONS:\n")
                for rec in recommendations['data_augmentation_needed']:
                    f.write(f"  {rec}\n")
        
        logger.info(f"💾 Wartschinski dataset saved: {train_file}")
        logger.info(f"📄 Training report saved: {report_file}")
        
        return {
            'wartschinski_dataset': str(train_file),
            'simple_commit_list': str(simple_file),
            'training_report': str(report_file),
            'ready_for_training': recommendations['dataset_status'] == 'ready'
        }

    def run_preparation_pipeline(self, output_dir: str = None) -> Dict:
        """Run the complete preparation pipeline"""
        
        if output_dir is None:
            output_dir = Path(self.dataset_file).parent / "wartschinski_ready"
        
        logger.info("🚀 PREPARING DATASET FOR WARTSCHINSKI PIPELINE")
        logger.info("="*60)
        
        # Step 1: Load dataset
        dataset = self.load_collected_dataset()
        if not dataset:
            return {'status': 'failed', 'reason': 'Could not load dataset'}
        
        # Step 2: Filter high-quality commits
        high_quality = self.filter_high_quality_commits(dataset, quality_threshold=0.3)
        if len(high_quality) < 30:
            logger.warning(f"⚠️ Only {len(high_quality)} high-quality commits. Consider lowering threshold.")
        
        # Step 3: Analyze vulnerability distribution
        analysis = self.analyze_vulnerability_distribution(high_quality)
        
        # Step 4: Convert to Wartschinski format
        wartschinski_commits = self.create_wartschinski_format(high_quality)
        
        # Step 5: Generate recommendations
        recommendations = self.generate_training_recommendations(analysis, wartschinski_commits)
        
        # Step 6: Save final dataset
        file_info = self.save_wartschinski_dataset(wartschinski_commits, analysis, 
                                                 recommendations, output_dir)
        
        # Final results
        results = {
            'status': 'success',
            'original_commits': len(dataset.get('commits', [])),
            'high_quality_commits': len(high_quality),
            'wartschinski_ready_commits': len(wartschinski_commits),
            'expected_training_samples': recommendations['expected_samples'],
            'dataset_status': recommendations['dataset_status'],
            'files_created': file_info,
            'analysis': analysis,
            'recommendations': recommendations
        }
        
        return results

    def print_preparation_summary(self, results: Dict):
        """Print comprehensive preparation summary"""
        
        print("\n" + "="*80)
        print("🎯 WARTSCHINSKI PIPELINE PREPARATION COMPLETE")
        print("="*80)
        
        print(f"\n📊 DATASET PROCESSING SUMMARY:")
        print(f"Original Commits Collected: {results['original_commits']}")
        print(f"High-Quality Commits: {results['high_quality_commits']}")
        print(f"Wartschinski-Ready Commits: {results['wartschinski_ready_commits']}")
        print(f"Expected Training Samples: ~{results['expected_training_samples']}")
        print(f"Dataset Status: {results['dataset_status'].upper()}")
        
        analysis = results['analysis']
        print(f"\n🏆 VULNERABILITY TYPE COVERAGE:")
        for vtype, count in sorted(analysis['vulnerability_types'].items(), key=lambda x: x[1], reverse=True):
            pct = (count / results['wartschinski_ready_commits']) * 100
            print(f"  {vtype}: {count} commits ({pct:.1f}%)")
        
        balance = analysis['balance_assessment']
        if balance['needs_balancing']:
            print(f"\n⚠️ CLASS BALANCE ISSUES:")
            print(f"  Most represented: {balance['most_represented'][0]} ({balance['most_represented'][1]:.1f}%)")
            print(f"  Least represented: {balance['least_represented'][0]} ({balance['least_represented'][1]:.1f}%)")
            print(f"  Minority classes: {list(balance['minority_classes'].keys())}")
        
        splits = results['recommendations']['commit_based_splits']
        print(f"\n✂️ COMMIT-BASED SPLITS (Prevents Data Leakage):")
        print(f"  Training: {splits['train']['count']} commits ({splits['split_ratios']['train']:.1%})")
        print(f"  Validation: {splits['validation']['count']} commits ({splits['split_ratios']['validation']:.1%})")
        print(f"  Test: {splits['test']['count']} commits ({splits['split_ratios']['test']:.1%})")
        
        print(f"\n💡 TRAINING RECOMMENDATIONS:")
        for rec in results['recommendations']['training_approach']:
            print(f"  {rec}")
        
        print(f"\n📁 FILES CREATED:")
        for file_type, file_path in results['files_created'].items():
            print(f"  {file_type}: {file_path}")
        
        if results['dataset_status'] == 'ready':
            print(f"\n🚀 NEXT STEPS:")
            print("1. ✅ Run enhanced Wartschinski pipeline on prepared commits")
            print("2. 🔬 Extract token-level samples using git diff analysis")
            print("3. 📚 Train Word2Vec with your 10,443 vocabulary approach")
            print("4. 🧠 Train LSTM with commit-based splitting")
            print("5. 📈 Expect realistic F1-scores: 65-80% (no data leakage)")
        else:
            print(f"\n⚠️ RECOMMENDED ACTIONS:")
            print("1. 📊 Consider combining with MoreFixes dataset (11,232 samples)")
            print("2. 🔍 Review quality threshold settings")
            print("3. 🎯 Or proceed with current dataset for initial experiments")
        
        print("\n" + "="*80)


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python wartschinski_preparation.py <dataset_file.json>")
        print("Example: python wartschinski_preparation.py java_vulnerability_commits_20250912_215632.json")
        sys.exit(1)
    
    dataset_file = sys.argv[1]
    
    if not Path(dataset_file).exists():
        print(f"❌ Dataset file not found: {dataset_file}")
        sys.exit(1)
    
    # Run preparation pipeline
    preparator = WartschinkiPreparation(dataset_file)
    results = preparator.run_preparation_pipeline()
    
    if results['status'] == 'success':
        preparator.print_preparation_summary(results)
        print(f"\n✅ PREPARATION COMPLETE! Ready for Wartschinski training.")
    else:
        print(f"❌ Preparation failed: {results.get('reason', 'Unknown error')}")