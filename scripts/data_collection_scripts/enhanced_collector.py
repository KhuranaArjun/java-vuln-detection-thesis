#!/usr/bin/env python3
"""
Enhanced Vulnerability Collector V2
Targeted collection for specific vulnerability types following Wartschinski's methodology
"""

import requests
import json
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnhancedVulnerabilityCollectorV2:
    def __init__(self, github_token: str):
        self.github_token = github_token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        # Targeted vulnerability type collection strategies
        self.vulnerability_strategies = {
            'sql_injection': {
                'target_samples': 1000,
                'current_samples': 280,
                'keywords': [
                    'SQL injection fix', 'SQLi fix', 'prepared statement',
                    'parameterized query', 'sql injection vulnerability',
                    'statement injection', 'database injection'
                ],
                'code_patterns': [
                    'prepareStatement', 'setString', 'setInt', 'executeQuery',
                    'createStatement', 'Statement', 'PreparedStatement'
                ],
                'frameworks': ['hibernate', 'mybatis', 'spring-data', 'jpa']
            },
            'xss': {
                'target_samples': 800,
                'current_samples': 92,
                'keywords': [
                    'XSS fix', 'cross-site scripting', 'HTML injection',
                    'script injection', 'output encoding', 'input sanitization'
                ],
                'code_patterns': [
                    'getParameter', 'getWriter', 'print', 'response.write',
                    'setAttribute', 'innerHTML', 'escapeHtml'
                ],
                'frameworks': ['spring-mvc', 'struts', 'jsf', 'servlet']
            },
            'command_injection': {
                'target_samples': 600,
                'current_samples': 350,
                'keywords': [
                    'command injection', 'OS command injection', 'shell injection',
                    'process execution', 'runtime exec'
                ],
                'code_patterns': [
                    'Runtime.exec', 'ProcessBuilder', 'Process.start',
                    'getRuntime', 'exec', 'shell'
                ],
                'frameworks': ['commons-exec', 'apache-commons']
            },
            'deserialization': {
                'target_samples': 500,
                'current_samples': 41,
                'keywords': [
                    'deserialization', 'unsafe deserialization', 'object injection',
                    'serialization vulnerability', 'readObject'
                ],
                'code_patterns': [
                    'ObjectInputStream', 'readObject', 'deserialize',
                    'Serializable', 'ObjectInput', 'readUnshared'
                ],
                'frameworks': ['jackson', 'gson', 'kryo', 'xstream']
            },
            'xxe': {
                'target_samples': 300,
                'current_samples': 19,
                'keywords': [
                    'XXE', 'XML external entity', 'XML injection',
                    'external entity', 'XML parser'
                ],
                'code_patterns': [
                    'DocumentBuilder', 'SAXParser', 'XMLReader',
                    'TransformerFactory', 'DocumentBuilderFactory'
                ],
                'frameworks': ['dom4j', 'jdom', 'xml-apis']
            },
            'csrf': {
                'target_samples': 300,
                'current_samples': 143,
                'keywords': [
                    'CSRF', 'cross-site request forgery', 'CSRF token',
                    'request forgery', 'anti-CSRF'
                ],
                'code_patterns': [
                    'HttpSession', 'getSession', 'csrf', 'token',
                    'RequestMapping', 'PostMapping'
                ],
                'frameworks': ['spring-security', 'spring-mvc']
            }
        }
        
        # High-quality repository targets
        self.priority_repositories = {
            'spring_ecosystem': [
                'spring-projects/spring-boot',
                'spring-projects/spring-framework',
                'spring-projects/spring-security',
                'spring-projects/spring-data-jpa'
            ],
            'apache_projects': [
                'apache/struts', 'apache/tomcat', 'apache/kafka',
                'apache/commons-collections', 'apache/commons-fileupload',
                'apache/shiro', 'apache/logging-log4j2'
            ],
            'serialization_libs': [
                'FasterXML/jackson-databind', 'google/gson',
                'EsotericSoftware/kryo', 'x-stream/xstream'
            ],
            'web_frameworks': [
                'eclipse/jetty.project', 'undertow-io/undertow',
                'netty/netty', 'AsyncHttpClient/async-http-client'
            ],
            'security_focused': [
                'OWASP/java-html-sanitizer', 'OWASP/ESAPI-Java',
                'OWASP/dependency-check', 'find-sec-bugs/find-sec-bugs'
            ]
        }
    
    def calculate_collection_priority(self) -> Dict[str, int]:
        """Calculate collection priority based on current gaps"""
        priorities = {}
        
        for vuln_type, config in self.vulnerability_strategies.items():
            current = config['current_samples']
            target = config['target_samples']
            gap = max(0, target - current)
            priority = gap / target  # Priority as percentage of target needed
            
            priorities[vuln_type] = {
                'gap': gap,
                'priority': priority,
                'commits_needed': gap // 15  # Estimate ~15 samples per commit
            }
            
            logger.info(f"{vuln_type}: Need {gap} more samples (Priority: {priority:.2f})")
        
        return priorities
    
    def search_targeted_repositories(self, vuln_type: str, max_repos: int = 30) -> List[Dict]:
        """Search for repositories likely to contain specific vulnerability types"""
        config = self.vulnerability_strategies[vuln_type]
        repositories = []
        
        # Strategy 1: Search by vulnerability keywords + framework
        for framework in config['frameworks']:
            for keyword in config['keywords'][:3]:  # Limit to top 3 keywords
                query = f'language:java {keyword} {framework} stars:>5'
                repos = self.search_repositories_with_query(query, max_repos=10)
                repositories.extend(repos)
                time.sleep(2)
        
        # Strategy 2: Search priority repositories for this vulnerability type
        for repo_category, repo_list in self.priority_repositories.items():
            if any(framework in repo_category for framework in config['frameworks']):
                for repo_name in repo_list:
                    repo_info = self.get_repository_info(repo_name)
                    if repo_info:
                        repositories.append(repo_info)
        
        # Strategy 3: CVE-related search
        cve_query = f'language:java CVE {vuln_type.replace("_", " ")} stars:>3'
        cve_repos = self.search_repositories_with_query(cve_query, max_repos=15)
        repositories.extend(cve_repos)
        
        # Remove duplicates
        unique_repos = []
        seen_names = set()
        for repo in repositories:
            if repo['name'] not in seen_names:
                unique_repos.append(repo)
                seen_names.add(repo['name'])
        
        logger.info(f"Found {len(unique_repos)} repositories for {vuln_type}")
        return unique_repos[:max_repos]
    
    def search_repositories_with_query(self, query: str, max_repos: int = 20) -> List[Dict]:
        """Search repositories with specific query"""
        repositories = []
        page = 1
        
        while len(repositories) < max_repos and page <= 5:
            try:
                url = f"{self.base_url}/search/repositories"
                params = {
                    'q': query,
                    'sort': 'updated',
                    'order': 'desc',
                    'per_page': 50,
                    'page': page
                }
                
                response = requests.get(url, headers=self.headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    repos = data.get('items', [])
                    
                    for repo in repos:
                        if self.is_quality_repository(repo):
                            repositories.append({
                                'name': repo['full_name'],
                                'id': repo['id'],
                                'stars': repo['stargazers_count'],
                                'language': repo['language'],
                                'updated_at': repo['updated_at']
                            })
                
                page += 1
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error searching repositories: {e}")
                break
        
        return repositories
    
    def get_repository_info(self, repo_name: str) -> Optional[Dict]:
        """Get information for a specific repository"""
        try:
            url = f"{self.base_url}/repos/{repo_name}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                repo = response.json()
                if self.is_quality_repository(repo):
                    return {
                        'name': repo['full_name'],
                        'id': repo['id'],
                        'stars': repo['stargazers_count'],
                        'language': repo['language'],
                        'updated_at': repo['updated_at']
                    }
        except Exception as e:
            logger.error(f"Error getting repository info for {repo_name}: {e}")
        
        return None
    
    def is_quality_repository(self, repo: Dict) -> bool:
        """Enhanced quality check for repositories"""
        repo_name = repo['full_name'].lower()
        description = (repo.get('description') or '').lower()
        
        # Exclude demo/educational repositories
        exclude_terms = [
            'demo', 'tutorial', 'example', 'sample', 'test', 'ctf',
            'vulnerable', 'exploit', 'poc', 'proof-of-concept',
            'learning', 'educational', 'practice'
        ]
        
        for term in exclude_terms:
            if term in repo_name or term in description:
                return False
        
        # Quality requirements
        if (repo.get('language') != 'Java' or
            repo.get('stargazers_count', 0) < 3 or
            repo.get('size', 0) < 50):
            return False
        
        return True
    
    def search_vulnerability_commits_targeted(self, repo_name: str, vuln_type: str, 
                                            max_commits: int = 25) -> List[Dict]:
        """Search for specific vulnerability type commits in repository"""
        config = self.vulnerability_strategies[vuln_type]
        commits = []
        
        # Search with vulnerability-specific keywords
        for keyword in config['keywords']:
            try:
                url = f"{self.base_url}/search/commits"
                params = {
                    'q': f'repo:{repo_name} "{keyword}"',
                    'sort': 'committer-date',
                    'order': 'desc',
                    'per_page': 20
                }
                
                headers = self.headers.copy()
                headers['Accept'] = 'application/vnd.github.cloak-preview'
                
                response = requests.get(url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    for commit in data.get('items', []):
                        if len(commits) >= max_commits:
                            break
                        
                        if self.is_quality_vulnerability_commit(commit, vuln_type):
                            commits.append({
                                'sha': commit['sha'],
                                'message': commit['commit']['message'],
                                'author': commit['commit']['author']['name'],
                                'date': commit['commit']['author']['date'],
                                'url': commit['html_url'],
                                'keyword_matched': keyword,
                                'vulnerability_type': vuln_type,
                                'repository': repo_name
                            })
                
                time.sleep(2)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Error searching commits for {keyword}: {e}")
                continue
            
            if len(commits) >= max_commits:
                break
        
        logger.info(f"Found {len(commits)} {vuln_type} commits in {repo_name}")
        return commits
    
    def is_quality_vulnerability_commit(self, commit: Dict, vuln_type: str) -> bool:
        """Enhanced commit validation for specific vulnerability types"""
        message = commit['commit']['message'].lower()
        config = self.vulnerability_strategies[vuln_type]
        
        # Must contain vulnerability-related terms
        vuln_score = 0
        for keyword in config['keywords']:
            if keyword.lower() in message:
                vuln_score += 1
        
        if vuln_score == 0:
            return False
        
        # Must contain fix-related terms
        fix_terms = ['fix', 'patch', 'resolve', 'prevent', 'secure', 'sanitize', 'validate']
        if not any(term in message for term in fix_terms):
            return False
        
        # Should contain code-related patterns
        code_score = 0
        for pattern in config['code_patterns']:
            if pattern.lower() in message:
                code_score += 1
        
        # Exclude obvious non-fixes
        exclude_terms = ['merge', 'revert', 'format', 'style', 'comment', 'doc', 'readme']
        if any(term in message for term in exclude_terms):
            return False
        
        # Require either high vulnerability score or some code patterns
        return vuln_score >= 2 or code_score >= 1
    
    def collect_targeted_vulnerabilities(self, output_file: str = 'enhanced_vulnerability_commits_v2.json'):
        """Run targeted collection for all vulnerability types"""
        logger.info("Starting enhanced targeted vulnerability collection...")
        
        priorities = self.calculate_collection_priority()
        all_commits = []
        
        # Sort vulnerability types by priority (highest first)
        sorted_vulns = sorted(priorities.items(), 
                            key=lambda x: x[1]['priority'], 
                            reverse=True)
        
        for vuln_type, priority_info in sorted_vulns:
            if priority_info['gap'] <= 0:
                logger.info(f"Skipping {vuln_type} - target already met")
                continue
            
            logger.info(f"Collecting {vuln_type} (Priority: {priority_info['priority']:.2f})")
            logger.info(f"Target: {priority_info['gap']} more samples")
            
            # Search for repositories
            repositories = self.search_targeted_repositories(vuln_type, max_repos=25)
            
            vuln_commits = []
            for repo in repositories:
                repo_name = repo['name']
                logger.info(f"  Processing {repo_name} for {vuln_type}")
                
                commits = self.search_vulnerability_commits_targeted(
                    repo_name, vuln_type, max_commits=15
                )
                
                # Get commit diffs
                for commit in commits:
                    diff_info = self.get_commit_diff_with_validation(
                        repo_name, commit['sha'], vuln_type
                    )
                    if diff_info:
                        diff_info['collection_strategy'] = 'targeted_v2'
                        diff_info['target_vulnerability'] = vuln_type
                        vuln_commits.append(diff_info)
                
                time.sleep(1)  # Be nice to API
                
                # Stop if we have enough commits for this vulnerability type
                if len(vuln_commits) >= priority_info['commits_needed']:
                    break
            
            all_commits.extend(vuln_commits)
            logger.info(f"Collected {len(vuln_commits)} commits for {vuln_type}")
            
            # Save intermediate results
            with open(f"intermediate_{vuln_type}_commits.json", 'w') as f:
                json.dump(vuln_commits, f, indent=2)
        
        # Save final results
        logger.info(f"Saving {len(all_commits)} enhanced commits to {output_file}")
        with open(output_file, 'w') as f:
            json.dump(all_commits, f, indent=2)
        
        # Generate collection report
        self.generate_collection_report(all_commits, output_file)
        
        return all_commits
    
    def get_commit_diff_with_validation(self, repo_name: str, commit_sha: str, 
                                      vuln_type: str) -> Optional[Dict]:
        """Get commit diff with vulnerability-specific validation"""
        try:
            url = f"{self.base_url}/repos/{repo_name}/commits/{commit_sha}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                
                # Filter for Java files with relevant changes
                java_files = []
                config = self.vulnerability_strategies[vuln_type]
                
                for file_info in data.get('files', []):
                    filename = file_info.get('filename', '')
                    patch = file_info.get('patch', '')
                    
                    if filename.endswith('.java') and patch:
                        # Check if patch contains vulnerability-related patterns
                        patch_lower = patch.lower()
                        pattern_score = sum(1 for pattern in config['code_patterns'] 
                                          if pattern.lower() in patch_lower)
                        
                        if pattern_score > 0:  # Must contain relevant code patterns
                            java_files.append({
                                'filename': filename,
                                'status': file_info.get('status'),
                                'additions': file_info.get('additions', 0),
                                'deletions': file_info.get('deletions', 0),
                                'patch': patch,
                                'raw_url': file_info.get('raw_url'),
                                'pattern_score': pattern_score
                            })
                
                if java_files:
                    return {
                        'sha': commit_sha,
                        'message': data['commit']['message'],
                        'author': data['commit']['author'],
                        'date': data['commit']['author']['date'],
                        'repository': repo_name,
                        'java_files': java_files,
                        'stats': data.get('stats', {}),
                        'url': data.get('html_url'),
                        'validated_vulnerability_type': vuln_type
                    }
        
        except Exception as e:
            logger.error(f"Error getting commit diff for {commit_sha}: {e}")
        
        return None
    
    def generate_collection_report(self, commits: List[Dict], output_file: str):
        """Generate detailed collection report"""
        report = {
            'collection_timestamp': datetime.now().isoformat(),
            'total_commits_collected': len(commits),
            'vulnerability_breakdown': {},
            'repository_breakdown': {},
            'collection_strategy': 'enhanced_targeted_v2',
            'quality_metrics': {
                'avg_pattern_score': 0,
                'commits_with_validation': 0,
                'unique_repositories': 0
            }
        }
        
        # Analyze by vulnerability type
        for commit in commits:
            vuln_type = commit.get('validated_vulnerability_type', 'unknown')
            if vuln_type not in report['vulnerability_breakdown']:
                report['vulnerability_breakdown'][vuln_type] = 0
            report['vulnerability_breakdown'][vuln_type] += 1
            
            # Repository breakdown
            repo = commit.get('repository', 'unknown')
            if repo not in report['repository_breakdown']:
                report['repository_breakdown'][repo] = 0
            report['repository_breakdown'][repo] += 1
        
        # Quality metrics
        report['quality_metrics']['unique_repositories'] = len(report['repository_breakdown'])
        report['quality_metrics']['commits_with_validation'] = len([
            c for c in commits if 'validated_vulnerability_type' in c
        ])
        
        # Save report
        report_file = output_file.replace('.json', '_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Collection report saved to {report_file}")
        
        # Print summary
        print("\n" + "="*60)
        print("📊 ENHANCED COLLECTION REPORT")
        print("="*60)
        print(f"Total commits collected: {len(commits)}")
        print(f"Unique repositories: {report['quality_metrics']['unique_repositories']}")
        print("\nVulnerability type breakdown:")
        for vuln_type, count in sorted(report['vulnerability_breakdown'].items()):
            print(f"  {vuln_type}: {count} commits")
        print("="*60)

# Example usage
if __name__ == "__main__":
    # Load GitHub token
    try:
        with open('github_token.txt', 'r') as f:
            token = f.read().strip()
    except FileNotFoundError:
        print("Please create github_token.txt with your GitHub token")
        exit(1)
    
    collector = EnhancedVulnerabilityCollectorV2(token)
    commits = collector.collect_targeted_vulnerabilities()
    
    print(f"\nEnhanced collection complete! Collected {len(commits)} targeted commits")