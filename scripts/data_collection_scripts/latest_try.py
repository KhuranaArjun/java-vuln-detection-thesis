#!/usr/bin/env python3
"""
Optimal Java Vulnerability Collector
Focused, simple approach to collect balanced vulnerability samples
"""

import requests
import json
import time
import logging
from datetime import datetime, timedelta
import hashlib
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OptimalJavaVulnerabilityCollector:
    def __init__(self, github_token):
        self.github_token = github_token
        self.headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = 'https://api.github.com'
        
        # Simplified search strategies that actually work with GitHub's commit search API
        self.vulnerability_searches = {
            'sql_injection': [
                'language:java "sql injection"',
                'language:java sqli',
                'language:java "prepared statement"',
                'language:java "parameterized query"',
                'language:java hibernate sql'
            ],
            'xss': [
                'language:java xss',
                'language:java "cross-site scripting"',
                'language:java "html escape"',
                'language:java "output encoding"',
                'language:java spring xss'
            ],
            'command_injection': [
                'language:java "command injection"',
                'language:java "process execution"',
                'language:java "runtime exec"',
                'language:java "command execution"'
            ],
            'path_traversal': [
                'language:java "path traversal"',
                'language:java "directory traversal"',
                'language:java "../"',
                'language:java "file inclusion"'
            ],
            'deserialization': [
                'language:java deserialization',
                'language:java "unsafe deserialization"',
                'language:java jackson deserialization',
                'language:java "object injection"'
            ],
            'csrf': [
                'language:java csrf',
                'language:java "cross-site request forgery"',
                'language:java "csrf token"',
                'language:java spring csrf'
            ],
            'xxe': [
                'language:java xxe',
                'language:java "xml external entity"',
                'language:java "xml injection"',
                'language:java "entity expansion"'
            ]
        }
        
        # Target commits per vulnerability type
        self.target_commits_per_type = {
            'sql_injection': 30,
            'xss': 25,
            'command_injection': 25,
            'path_traversal': 20,
            'deserialization': 20,
            'csrf': 20,
            'xxe': 15
        }
    
    def search_commits_for_vulnerability(self, vulnerability_type, max_commits=30):
        """Search for commits of a specific vulnerability type"""
        logger.info(f"Searching for {vulnerability_type} vulnerabilities...")
        
        all_commits = []
        search_queries = self.vulnerability_searches[vulnerability_type]
        
        for query in search_queries:
            if len(all_commits) >= max_commits:
                break
                
            commits = self.search_github_commits(query, per_page=10)
            for commit in commits:
                if len(all_commits) >= max_commits:
                    break
                    
                # Add vulnerability type metadata
                commit['target_vulnerability_type'] = vulnerability_type
                commit['search_query'] = query
                all_commits.append(commit)
            
            # Rate limiting
            time.sleep(2)
        
        # Remove duplicates by SHA
        unique_commits = []
        seen_shas = set()
        for commit in all_commits:
            sha = commit.get('sha', '')
            if sha and sha not in seen_shas:
                seen_shas.add(sha)
                unique_commits.append(commit)
        
        logger.info(f"Found {len(unique_commits)} unique {vulnerability_type} commits")
        return unique_commits[:max_commits]
    
    def search_github_commits(self, query, per_page=30):
        """Search GitHub commits with given query"""
        url = f"{self.base_url}/search/commits"
        params = {
            'q': query,
            'sort': 'committer-date',
            'order': 'desc',
            'per_page': per_page
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 403:
                logger.warning("Rate limit hit, waiting...")
                time.sleep(60)
                return []
            
            if response.status_code == 422:
                logger.warning(f"Query too complex, skipping: {query}")
                return []
            
            response.raise_for_status()
            data = response.json()
            
            commits = []
            for item in data.get('items', []):
                commit_detail = self.get_commit_details(
                    item['repository']['full_name'], 
                    item['sha']
                )
                if commit_detail:
                    commits.append(commit_detail)
                    
                time.sleep(0.5)  # Rate limiting
            
            return commits
            
        except Exception as e:
            logger.error(f"Error searching commits: {e}")
            return []
    
    def get_commit_details(self, repo_name, sha):
        """Get detailed commit information"""
        url = f"{self.base_url}/repos/{repo_name}/commits/{sha}"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            commit_data = response.json()
            
            # Extract Java files and patches
            java_files = []
            for file_data in commit_data.get('files', []):
                filename = file_data.get('filename', '')
                if filename.endswith(('.java', '.jsp', '.jsf')):
                    java_files.append({
                        'filename': filename,
                        'patch': file_data.get('patch', ''),
                        'additions': file_data.get('additions', 0),
                        'deletions': file_data.get('deletions', 0),
                        'changes': file_data.get('changes', 0)
                    })
            
            if not java_files:
                return None
            
            return {
                'sha': sha,
                'repository': repo_name,
                'message': commit_data['commit']['message'],
                'author': commit_data['commit']['author']['name'],
                'date': commit_data['commit']['author']['date'],
                'java_files': java_files,
                'total_additions': sum(f['additions'] for f in java_files),
                'total_deletions': sum(f['deletions'] for f in java_files),
                'url': commit_data['html_url']
            }
            
        except Exception as e:
            logger.error(f"Error getting commit details for {repo_name}/{sha}: {e}")
            return None
    
    def validate_commit_quality(self, commit):
        """Simple but effective quality validation"""
        # Must have meaningful changes
        if commit['total_additions'] + commit['total_deletions'] < 3:
            return False, "too_few_changes"
        
        # Must have Java files
        if not commit['java_files']:
            return False, "no_java_files"
        
        # Must have patches
        if not any(f.get('patch') for f in commit['java_files']):
            return False, "no_patches"
        
        # Message shouldn't be too short
        if len(commit['message']) < 10:
            return False, "short_message"
        
        return True, "valid"
    
    def collect_balanced_dataset(self, output_file='optimal_java_vulnerabilities.json'):
        """Collect balanced vulnerability dataset"""
        logger.info("Starting optimal Java vulnerability collection...")
        
        all_commits = []
        collection_stats = {}
        
        for vuln_type, target_count in self.target_commits_per_type.items():
            logger.info(f"\n--- Collecting {vuln_type} vulnerabilities ---")
            
            # Search for this vulnerability type
            raw_commits = self.search_commits_for_vulnerability(vuln_type, target_count + 10)
            
            # Quality validation
            valid_commits = []
            validation_stats = {'total': len(raw_commits), 'valid': 0, 'rejected': 0}
            
            for commit in raw_commits:
                is_valid, reason = self.validate_commit_quality(commit)
                if is_valid:
                    valid_commits.append(commit)
                    validation_stats['valid'] += 1
                else:
                    validation_stats['rejected'] += 1
                    
                if len(valid_commits) >= target_count:
                    break
            
            all_commits.extend(valid_commits)
            collection_stats[vuln_type] = {
                'target': target_count,
                'collected': len(valid_commits),
                'validation_stats': validation_stats
            }
            
            logger.info(f"Collected {len(valid_commits)}/{target_count} {vuln_type} commits")
        
        # Save results
        logger.info(f"\nSaving {len(all_commits)} commits to {output_file}")
        with open(output_file, 'w') as f:
            json.dump(all_commits, f, indent=2)
        
        # Save statistics
        stats_file = output_file.replace('.json', '_stats.json')
        with open(stats_file, 'w') as f:
            json.dump({
                'collection_date': datetime.now().isoformat(),
                'total_commits': len(all_commits),
                'vulnerability_distribution': collection_stats,
                'summary': {
                    vuln_type: stats['collected'] 
                    for vuln_type, stats in collection_stats.items()
                }
            }, f, indent=2)
        
        self.print_collection_summary(collection_stats, len(all_commits))
        return all_commits
    
    def print_collection_summary(self, stats, total_commits):
        """Print collection summary"""
        print("\n" + "="*60)
        print("UNLIMITED JAVA VULNERABILITY COLLECTION RESULTS")
        print("="*60)
        print(f"Total commits collected: {total_commits}")
        print("\nVulnerability type breakdown:")
        
        for vuln_type, data in stats.items():
            print(f"  {vuln_type}: {data['collected']} commits")
        
        print("\nEstimated samples (assuming ~15 samples per commit):")
        estimated_samples = total_commits * 15
        print(f"  Total estimated samples: {estimated_samples}")
        
        print("="*60)

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Optimal Java Vulnerability Collector")
    parser.add_argument('--token', required=True, help='GitHub API token')
    parser.add_argument('--output', default='optimal_java_vulnerabilities.json', 
                      help='Output file for commits')
    
    args = parser.parse_args()
    
    collector = OptimalJavaVulnerabilityCollector(args.token)
    commits = collector.collect_balanced_dataset(args.output)
    
    print(f"\nSuccess! Collected {len(commits)} commits")
    print("Next step: Run java_dataset_processor.py on this data")

if __name__ == "__main__":
    main()