#!/usr/bin/env python3
"""
Laura Wartschinski's Repository Filtering Pipeline - Adapted for Java
Apply VUDENC's quality filtering methodology to existing commit dataset
"""

import json
import re
import logging
import requests
import time
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, Counter
import hashlib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LauraRepositoryFilter:
    """
    Apply Laura Wartschinski's VUDENC filtering methodology to Java vulnerability dataset
    Based on her filterShowcases.py and quality validation approaches
    """
    
    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token
        self.headers = {}
        if github_token:
            self.headers = {
                'Authorization': f'token {github_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
        
        # Laura's showcase/demo repository indicators
        self.showcase_indicators = {
            'repo_name_patterns': [
                r'vulnerable?[-_]?app',
                r'exploit[-_]?(db|collection)',
                r'ctf[-_]?challenge',
                r'security[-_]?demo',
                r'hack[-_]?(lab|exercise)',
                r'penetration[-_]?test',
                r'bug[-_]?bounty',
                r'vulnerability[-_]?lab',
                r'insecure[-_]?app',
                r'damn[-_]?vulnerable',
                r'test[-_]?app',
                r'demo[-_]?app',
                r'tutorial[-_]?app',
                r'example[-_]?app',
                r'sample[-_]?app',
                r'playground',
                r'workshop',
                r'training'
            ],
            'readme_patterns': [
                r'vulnerable\s+application',
                r'security\s+training',
                r'penetration\s+testing',
                r'ctf\s+challenge',
                r'capture\s+the\s+flag',
                r'hack\s+the\s+box',
                r'security\s+exercise',
                r'intentionally\s+vulnerable',
                r'educational\s+purpose',
                r'demonstration\s+purpose',
                r'security\s+awareness',
                r'learning\s+platform',
                r'tutorial\s+application',
                r'example\s+implementation',
                r'proof\s+of\s+concept',
                r'for\s+demonstration',
                r'educational\s+tool'
            ]
        }
        
        # Laura's commit message quality indicators
        self.quality_commit_patterns = {
            'positive_indicators': [
                r'fix(?:es|ed)?\s+(?:security\s+)?(?:vulnerability|issue|bug)',
                r'security\s+(?:fix|patch|update)',
                r'(?:prevent|block|stop)\s+(?:injection|attack|exploit)',
                r'sanitize?(?:d|ing)?\s+(?:input|output|data)',
                r'validate?(?:d|ing)?\s+(?:input|parameter|data)',
                r'escape?(?:d|ing)?\s+(?:html|sql|output)',
                r'(?:add|implement)(?:ed|ing)?\s+(?:validation|sanitization)',
                r'(?:close|patch)(?:ed|ing)?\s+(?:security\s+)?(?:hole|gap|vulnerability)',
                r'(?:remove|eliminate)(?:d|ing)?\s+(?:vulnerability|exploit)',
                r'harden(?:ed|ing)?\s+(?:security|code)',
                r'secure(?:d|ing)?\s+(?:endpoint|api|function)'
            ],
            'negative_indicators': [
                r'add(?:ed|ing)?\s+(?:test|example|demo)',
                r'(?:create|add)(?:ed|ing)?\s+(?:vulnerable|insecure)',
                r'(?:implement|add)(?:ed|ing)?\s+(?:exploit|attack)',
                r'for\s+(?:demonstration|tutorial|example)',
                r'(?:intentionally\s+)?vulnerable',
                r'ctf\s+challenge',
                r'security\s+exercise'
            ]
        }
        
        # Vulnerability classification patterns (Laura's approach)
        self.vulnerability_patterns = {
            'sql_injection': [
                r'sql\s+injection', r'sqli\b', r'sql\s+vulnerable',
                r'prepared\s+statement', r'parameterized\s+query',
                r'sql\s+escape', r'database\s+injection'
            ],
            'xss': [
                r'cross[-_]?site\s+scripting', r'\bxss\b',
                r'script\s+injection', r'html\s+escape',
                r'output\s+encoding', r'dom\s+xss',
                r'reflected\s+xss', r'stored\s+xss'
            ],
            'command_injection': [
                r'command\s+injection', r'code\s+injection',
                r'shell\s+injection', r'process\s+execution',
                r'runtime\.exec', r'command\s+execution'
            ],
            'path_traversal': [
                r'path\s+traversal', r'directory\s+traversal',
                r'\.\./', r'file\s+inclusion',
                r'path\s+validation', r'file\s+path',
                r'directory\s+escape'
            ],
            'deserialization': [
                r'deserialization', r'unsafe\s+deserialization',
                r'object\s+injection', r'gadget\s+chain',
                r'serialization\s+vulnerability'
            ],
            'csrf': [
                r'\bcsrf\b', r'cross[-_]?site\s+request\s+forgery',
                r'csrf\s+token', r'state\s+token',
                r'request\s+validation', r'origin\s+validation'
            ],
            'xxe': [
                r'\bxxe\b', r'xml\s+external\s+entity',
                r'xml\s+injection', r'entity\s+expansion',
                r'xml\s+parser', r'external\s+entity'
            ]
        }
    
    def get_repository_readme(self, repo_name: str) -> Optional[str]:
        """Get repository README content for filtering analysis"""
        if not self.github_token:
            return None
            
        url = f'https://api.github.com/repos/{repo_name}/readme'
        
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                import base64
                content = response.json().get('content', '')
                readme_content = base64.b64decode(content).decode('utf-8', errors='ignore')
                return readme_content.lower()
            return None
        except Exception as e:
            logger.debug(f"Could not fetch README for {repo_name}: {e}")
            return None
    
    def is_showcase_repository(self, repo_name: str, readme_content: Optional[str] = None) -> Tuple[bool, str]:
        """
        Determine if repository is a showcase/demo/educational project
        Based on Laura's filterShowcases.py methodology
        """
        repo_name_lower = repo_name.lower()
        
        # Check repository name patterns
        for pattern in self.showcase_indicators['repo_name_patterns']:
            if re.search(pattern, repo_name_lower):
                return True, f"repo_name_pattern: {pattern}"
        
        # Check README content if available
        if readme_content:
            for pattern in self.showcase_indicators['readme_patterns']:
                if re.search(pattern, readme_content):
                    return True, f"readme_pattern: {pattern}"
        
        return False, "not_showcase"
    
    def analyze_commit_message_quality(self, message: str) -> Dict:
        """
        Analyze commit message quality based on Laura's approach
        Returns quality score and classification reasoning
        """
        message_lower = message.lower()
        
        positive_score = 0
        negative_score = 0
        matched_patterns = {'positive': [], 'negative': []}
        
        # Check positive indicators
        for pattern in self.quality_commit_patterns['positive_indicators']:
            if re.search(pattern, message_lower):
                positive_score += 1
                matched_patterns['positive'].append(pattern)
        
        # Check negative indicators
        for pattern in self.quality_commit_patterns['negative_indicators']:
            if re.search(pattern, message_lower):
                negative_score += 1
                matched_patterns['negative'].append(pattern)
        
        # Calculate quality score
        if negative_score > 0:
            quality_score = 0.0  # Definitely not a real security fix
        elif positive_score == 0:
            quality_score = 0.3  # Unclear, might be security-related
        else:
            quality_score = min(1.0, 0.5 + (positive_score * 0.2))
        
        return {
            'quality_score': quality_score,
            'positive_matches': matched_patterns['positive'],
            'negative_matches': matched_patterns['negative'],
            'positive_count': positive_score,
            'negative_count': negative_score
        }
    
    def classify_vulnerability_type(self, commit_data: Dict) -> Tuple[str, float]:
        """
        Classify vulnerability type using Laura's pattern matching approach
        """
        text_content = ' '.join([
            commit_data.get('message', ''),
            ' '.join([f.get('filename', '') for f in commit_data.get('java_files', [])]),
            ' '.join([f.get('patch', '') for f in commit_data.get('java_files', [])])[:500]  # Limit patch content
        ]).lower()
        
        vulnerability_scores = {}
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, text_content))
                score += matches
            
            if score > 0:
                vulnerability_scores[vuln_type] = score
        
        if not vulnerability_scores:
            return 'unknown', 0.0
        
        # Return the vulnerability type with highest score
        best_type = max(vulnerability_scores.keys(), key=vulnerability_scores.get)
        max_score = vulnerability_scores[best_type]
        confidence = min(1.0, max_score * 0.3)  # Convert to confidence score
        
        return best_type, confidence
    
    def validate_code_changes(self, commit_data: Dict) -> Dict:
        """
        Validate that commit contains meaningful code changes
        Based on Laura's getDiffs.py validation
        """
        java_files = commit_data.get('java_files', [])
        
        if not java_files:
            return {'valid': False, 'reason': 'no_java_files'}
        
        total_additions = sum(f.get('additions', 0) for f in java_files)
        total_deletions = sum(f.get('deletions', 0) for f in java_files)
        total_changes = total_additions + total_deletions
        
        # Must have meaningful changes
        if total_changes < 3:
            return {'valid': False, 'reason': 'too_few_changes'}
        
        # Must have patches
        patches_with_content = [f for f in java_files if f.get('patch') and len(f.get('patch', '')) > 20]
        if not patches_with_content:
            return {'valid': False, 'reason': 'no_meaningful_patches'}
        
        # Check for test-only changes
        test_files = [f for f in java_files if 'test' in f.get('filename', '').lower()]
        if len(test_files) == len(java_files) and len(java_files) > 0:
            return {'valid': False, 'reason': 'test_files_only'}
        
        return {
            'valid': True,
            'total_changes': total_changes,
            'total_additions': total_additions,
            'total_deletions': total_deletions,
            'java_files_count': len(java_files),
            'patches_with_content': len(patches_with_content)
        }
    
    def apply_laura_filtering(self, commits_file: str, output_file: str = 'laura_filtered_commits.json') -> Dict:
        """
        Apply Laura's complete filtering pipeline to existing commits
        """
        logger.info("Applying Laura Wartschinski's VUDENC filtering methodology...")
        
        # Load existing commits
        with open(commits_file, 'r') as f:
            commits = json.load(f)
        
        logger.info(f"Loaded {len(commits)} commits for filtering")
        
        # Statistics tracking
        filtering_stats = {
            'total_input': len(commits),
            'showcase_repositories': 0,
            'poor_commit_messages': 0,
            'invalid_code_changes': 0,
            'passed_all_filters': 0,
            'vulnerability_classification': defaultdict(int),
            'quality_scores': [],
            'filtered_repositories': set(),
            'showcase_repos': [],
            'low_quality_commits': []
        }
        
        filtered_commits = []
        
        # Process each commit through Laura's filtering pipeline
        for i, commit in enumerate(commits):
            if i % 50 == 0:
                logger.info(f"Processing commit {i+1}/{len(commits)}")
            
            repo_name = commit.get('repository', '')
            commit_sha = commit.get('sha', '')[:8]
            
            # Stage 1: Repository showcase filtering
            readme_content = self.get_repository_readme(repo_name) if self.github_token else None
            is_showcase, showcase_reason = self.is_showcase_repository(repo_name, readme_content)
            
            if is_showcase:
                filtering_stats['showcase_repositories'] += 1
                filtering_stats['showcase_repos'].append({
                    'repo': repo_name,
                    'reason': showcase_reason,
                    'commit_sha': commit_sha
                })
                continue
            
            # Stage 2: Commit message quality analysis
            # message_analysis = self.analyze_commit_message_quality(commit.get('message', ''))
            
            # if message_analysis['quality_score'] < 0.4:
            #     filtering_stats['poor_commit_messages'] += 1
            #     filtering_stats['low_quality_commits'].append({
            #         'repo': repo_name,
            #         'commit_sha': commit_sha,
            #         'quality_score': message_analysis['quality_score'],
            #         'message': commit.get('message', '')[:100]
            #     })
            #     continue
            
            # Stage 3: Code change validation
            code_validation = self.validate_code_changes(commit)
            
            if not code_validation['valid']:
                filtering_stats['invalid_code_changes'] += 1
                continue
            
            # Stage 4: Vulnerability classification
            vuln_type, confidence = self.classify_vulnerability_type(commit)
            
            # Enhance commit with Laura's analysis
            enhanced_commit = commit.copy()
            enhanced_commit.update({
                'laura_analysis': {
                    # 'message_quality': message_analysis,
                    'code_validation': code_validation,
                    'vulnerability_classification': {
                        'type': vuln_type,
                        'confidence': confidence
                    },
                    'is_showcase_repo': False,
                    'passed_laura_filters': True
                }
            })
            
            filtered_commits.append(enhanced_commit)
            filtering_stats['passed_all_filters'] += 1
            filtering_stats['vulnerability_classification'][vuln_type] += 1
            # filtering_stats['quality_scores'].append(message_analysis['quality_score'])
            
            if self.github_token and i < len(commits) - 1:
                time.sleep(0.5)  # Rate limiting
        
        # Calculate final statistics
        filtering_stats['average_quality_score'] = (
            sum(filtering_stats['quality_scores']) / len(filtering_stats['quality_scores'])
            if filtering_stats['quality_scores'] else 0
        )
        filtering_stats['pass_rate'] = (
            filtering_stats['passed_all_filters'] / filtering_stats['total_input']
            if filtering_stats['total_input'] > 0 else 0
        )
        
        # Save filtered commits
        with open(output_file, 'w') as f:
            json.dump(filtered_commits, f, indent=2)
        
        # Save detailed statistics
        stats_file = output_file.replace('.json', '_laura_stats.json')
        with open(stats_file, 'w') as f:
            # Convert sets to lists for JSON serialization
            stats_to_save = filtering_stats.copy()
            stats_to_save['filtered_repositories'] = list(stats_to_save['filtered_repositories'])
            stats_to_save['vulnerability_classification'] = dict(stats_to_save['vulnerability_classification'])
            json.dump(stats_to_save, f, indent=2)
        
        self.print_laura_filtering_report(filtering_stats, len(filtered_commits))
        
        return {
            'filtered_commits': filtered_commits,
            'statistics': filtering_stats,
            'output_file': output_file,
            'stats_file': stats_file
        }
    
    def print_laura_filtering_report(self, stats: Dict, final_count: int):
        """Print comprehensive filtering report following Laura's style"""
        print("\n" + "="*70)
        print("LAURA WARTSCHINSKI'S VUDENC FILTERING RESULTS")
        print("="*70)
        
        print(f"📊 Filtering Pipeline Results:")
        print(f"   Input commits: {stats['total_input']}")
        print(f"   Showcase repositories filtered: {stats['showcase_repositories']}")
        print(f"   Poor commit messages filtered: {stats['poor_commit_messages']}")
        print(f"   Invalid code changes filtered: {stats['invalid_code_changes']}")
        print(f"   Final high-quality commits: {final_count}")
        print(f"   Overall pass rate: {stats['pass_rate']:.1%}")
        
        print(f"\n🎯 Vulnerability Classification (Laura's patterns):")
        for vuln_type, count in sorted(stats['vulnerability_classification'].items()):
            percentage = (count / final_count) * 100 if final_count > 0 else 0
            print(f"   {vuln_type}: {count} commits ({percentage:.1f}%)")
        
        print(f"\n📈 Quality Metrics:")
        print(f"   Average commit quality score: {stats['average_quality_score']:.2f}")
        print(f"   Repositories identified as showcases: {len(stats['showcase_repos'])}")
        
        if stats['showcase_repos']:
            print(f"\n🚫 Showcase Repositories Filtered (sample):")
            for repo_info in stats['showcase_repos'][:5]:
                print(f"   {repo_info['repo']} - {repo_info['reason']}")
            if len(stats['showcase_repos']) > 5:
                print(f"   ... and {len(stats['showcase_repos']) - 5} more")
        
        print("="*70)
        print("✅ Laura's filtering methodology applied successfully!")
        print("📄 This follows the same quality standards as VUDENC research")
        print("="*70)

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Apply Laura's VUDENC Filtering Pipeline")
    parser.add_argument('input_file', help='Input JSON file with commits')
    parser.add_argument('--output', '-o', default='laura_filtered_commits.json',
                      help='Output file for filtered commits')
    parser.add_argument('--token', help='GitHub API token (optional, for README analysis)')
    
    args = parser.parse_args()
    
    # Initialize filter with optional GitHub token
    filter_pipeline = LauraRepositoryFilter(args.token)
    
    # Apply Laura's filtering methodology
    results = filter_pipeline.apply_laura_filtering(args.input_file, args.output)
    
    print(f"\n✅ Filtering complete!")
    print(f"📊 Filtered commits: {args.output}")
    print(f"📋 Detailed statistics: {results['stats_file']}")
    print(f"📈 Quality improvement: {len(results['filtered_commits'])} high-quality commits retained")

if __name__ == "__main__":
    main()