#!/usr/bin/env python3
"""
Framework Systematic Collector
Systematic collection from popular Java frameworks following Wartschinski's methodology
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

class FrameworkSystematicCollector:
    def __init__(self, github_token: str):
        self.github_token = github_token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        # Systematic framework mapping with vulnerability propensities
        self.framework_ecosystem = {
            'spring_ecosystem': {
                'repositories': [
                    'spring-projects/spring-boot',
                    'spring-projects/spring-framework', 
                    'spring-projects/spring-security',
                    'spring-projects/spring-data-jpa',
                    'spring-projects/spring-web',
                    'spring-projects/spring-webmvc'
                ],
                'vulnerability_focus': ['xss', 'csrf', 'sql_injection', 'authentication'],
                'security_keywords': [
                    'CSRF protection', 'XSS prevention', 'SQL injection',
                    'authentication bypass', 'authorization', 'session fixation'
                ],
                'code_patterns': [
                    '@RequestMapping', '@PostMapping', '@GetMapping',
                    'HttpServletRequest', 'HttpSession', 'CSRF'
                ]
            },
            'apache_web': {
                'repositories': [
                    'apache/struts',
                    'apache/tomcat', 
                    'apache/commons-fileupload',
                    'apache/commons-collections',
                    'apache/shiro'
                ],
                'vulnerability_focus': ['command_injection', 'deserialization', 'path_traversal'],
                'security_keywords': [
                    'remote code execution', 'deserialization', 'file upload',
                    'path traversal', 'directory traversal', 'arbitrary file'
                ],
                'code_patterns': [
                    'FileUpload', 'MultipartRequest', 'File.separator',
                    'getCanonicalPath', 'normalize'
                ]
            },
            'serialization_libs': {
                'repositories': [
                    'FasterXML/jackson-databind',
                    'FasterXML/jackson-core',
                    'google/gson',
                    'EsotericSoftware/kryo',
                    'x-stream/xstream'
                ],
                'vulnerability_focus': ['deserialization'],
                'security_keywords': [
                    'deserialization', 'unsafe deserialization', 'gadget chain',
                    'polymorphic deserialization', 'type validation'
                ],
                'code_patterns': [
                    'ObjectMapper', 'readValue', 'JsonTypeInfo',
                    'enableDefaultTyping', 'ObjectInputStream'
                ]
            },
            'xml_processing': {
                'repositories': [
                    'dom4j/dom4j',
                    'jdom-org/jdom2',
                    'apache/xerces2-j'
                ],
                'vulnerability_focus': ['xxe'],
                'security_keywords': [
                    'XXE', 'XML external entity', 'XML injection',
                    'external entity', 'DOCTYPE'
                ],
                'code_patterns': [
                    'DocumentBuilder', 'SAXParser', 'XMLReader',
                    'setFeature', 'FEATURE_SECURE_PROCESSING'
                ]
            },
            'logging_frameworks': {
                'repositories': [
                    'apache/logging-log4j2',
                    'qos-ch/logback',
                    'qos-ch/slf4j'
                ],
                'vulnerability_focus': ['command_injection', 'deserialization'],
                'security_keywords': [
                    'log injection', 'JNDI injection', 'lookup',
                    'remote code execution', 'log4shell'
                ],
                'code_patterns': [
                    'JNDI', 'lookup', 'log4j', 'LogManager',
                    'JndiLookup', 'formatMessage'
                ]
            },
            'database_frameworks': {
                'repositories': [
                    'hibernate/hibernate-orm',
                    'mybatis/mybatis-3',
                    'h2database/h2database',
                    'eclipse-ee4j/jpa-api'
                ],
                'vulnerability_focus': ['sql_injection'],
                'security_keywords': [
                    'SQL injection', 'HQL injection', 'query injection',
                    'prepared statement', 'parameterized query'
                ],
                'code_patterns': [
                    'createQuery', 'createNativeQuery', 'prepareStatement',
                    'Query.setParameter', 'NamedQuery'
                ]
            },
            'web_servers': {
                'repositories': [
                    'eclipse/jetty.project',
                    'undertow-io/undertow',
                    'netty/netty'
                ],
                'vulnerability_focus': ['xss', 'path_traversal', 'dos'],
                'security_keywords': [
                    'HTTP request smuggling', 'path traversal',
                    'denial of service', 'buffer overflow'
                ],
                'code_patterns': [
                    'HttpServletRequest', 'HttpServletResponse',
                    'getRequestURI', 'getPathInfo'
                ]
            }
        }
        
        # Time-based collection strategy
        self.time_periods = [
            ('2024-01-01', '2024-12-31', 'recent'),
            ('2023-01-01', '2023-12-31', '2023'),
            ('2022-01-01', '2022-12-31', '2022'),
            ('2021-01-01', '2021-12-31', '2021'),
            ('2020-01-01', '2020-12-31', '2020')
        ]
    
    def get_repository_security_profile(self, repo_name: str) -> Dict:
        """Get security-related profile for a repository"""
        try:
            # Get repository info
            url = f"{self.base_url}/repos/{repo_name}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                repo_data = response.json()
                
                # Get recent security-related activity
                security_profile = {
                    'name': repo_name,
                    'stars': repo_data.get('stargazers_count', 0),
                    'forks': repo_data.get('forks_count', 0),
                    'size': repo_data.get('size', 0),
                    'updated_at': repo_data.get('updated_at'),
                    'has_security_policy': False,
                    'security_advisories_count': 0,
                    'recent_security_commits': 0
                }
                
                # Check for security policy
                try:
                    security_url = f"{self.base_url}/repos/{repo_name}/community/profile"
                    sec_response = requests.get(security_url, headers=self.headers)
                    if sec_response.status_code == 200:
                        community_data = sec_response.json()
                        security_profile['has_security_policy'] = community_data.get('files', {}).get('security') is not None
                except:
                    pass
                
                # Get security advisories count
                try:
                    advisories_url = f"{self.base_url}/repos/{repo_name}/security-advisories"
                    adv_response = requests.get(advisories_url, headers=self.headers)
                    if adv_response.status_code == 200:
                        advisories = adv_response.json()
                        security_profile['security_advisories_count'] = len(advisories)
                except:
                    pass
                
                return security_profile
                
        except Exception as e:
            logger.error(f"Error getting security profile for {repo_name}: {e}")
        
        return None
    
    def search_framework_security_commits(self, framework_config: Dict, 
                                        repo_name: str, 
                                        time_period: tuple = None,
                                        max_commits: int = 30) -> List[Dict]:
        """Search for security commits in a specific framework repository"""
        
        commits = []
        vulnerability_focus = framework_config['vulnerability_focus']
        security_keywords = framework_config['security_keywords']
        
        # Build comprehensive search queries
        search_queries = []
        
        # Vulnerability-specific queries
        for vuln_type in vulnerability_focus:
            vuln_keywords = {
                'sql_injection': ['SQL injection', 'SQLi', 'prepared statement'],
                'xss': ['XSS', 'cross-site scripting', 'HTML injection'],
                'command_injection': ['command injection', 'RCE', 'remote code execution'],
                'deserialization': ['deserialization', 'unsafe deserialization'],
                'path_traversal': ['path traversal', 'directory traversal'],
                'xxe': ['XXE', 'XML external entity'],
                'csrf': ['CSRF', 'cross-site request forgery']
            }
            
            if vuln_type in vuln_keywords:
                for keyword in vuln_keywords[vuln_type]:
                    search_queries.append(keyword)
        
        # Add framework-specific security keywords
        search_queries.extend(security_keywords)
        
        # Add time period filter if specified
        date_filter = ""
        if time_period:
            start_date, end_date, period_name = time_period
            date_filter = f" committer-date:{start_date}..{end_date}"
        
        logger.info(f"Searching {repo_name} for security commits{' in ' + time_period[2] if time_period else ''}")
        
        for query in search_queries[:8]:  # Limit to avoid rate limits
            try:
                search_url = f"{self.base_url}/search/commits"
                full_query = f'repo:{repo_name} "{query}" fix{date_filter}'
                
                params = {
                    'q': full_query,
                    'sort': 'committer-date',
                    'order': 'desc',
                    'per_page': 15
                }
                
                headers = self.headers.copy()
                headers['Accept'] = 'application/vnd.github.cloak-preview'
                
                response = requests.get(search_url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for commit in data.get('items', []):
                        if len(commits) >= max_commits:
                            break
                        
                        if self.is_framework_security_commit(commit, framework_config):
                            commit_info = {
                                'sha': commit['sha'],
                                'message': commit['commit']['message'],
                                'author': commit['commit']['author']['name'],
                                'date': commit['commit']['author']['date'],
                                'url': commit['html_url'],
                                'query_matched': query,
                                'repository': repo_name,
                                'framework_category': self.get_framework_category(repo_name),
                                'collection_strategy': 'framework_systematic'
                            }
                            
                            if time_period:
                                commit_info['time_period'] = time_period[2]
                            
                            commits.append(commit_info)
                
                elif response.status_code == 403:
                    logger.warning("Rate limit hit, waiting...")
                    time.sleep(60)
                    break
                
                time.sleep(2)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Error searching commits with query '{query}': {e}")
                continue
            
            if len(commits) >= max_commits:
                break
        
        logger.info(f"Found {len(commits)} security commits in {repo_name}")
        return commits
    
    def is_framework_security_commit(self, commit: Dict, framework_config: Dict) -> bool:
        """Validate if commit is a legitimate security fix for the framework"""
        message = commit['commit']['message'].lower()
        
        # Must contain security-related terms
        security_terms = ['fix', 'patch', 'resolve', 'prevent', 'secure', 'vulnerability']
        if not any(term in message for term in security_terms):
            return False
        
        # Should contain framework-specific patterns or security keywords
        framework_score = 0
        
        # Check security keywords
        for keyword in framework_config['security_keywords']:
            if keyword.lower() in message:
                framework_score += 2
        
        # Check code patterns mentioned in commit
        for pattern in framework_config['code_patterns']:
            if pattern.lower() in message:
                framework_score += 1
        
        # Check vulnerability focus alignment
        vuln_keywords = []
        for vuln_type in framework_config['vulnerability_focus']:
            vuln_keywords.extend([
                vuln_type.replace('_', ' '), 
                vuln_type.replace('_', ''),
                vuln_type
            ])
        
        for keyword in vuln_keywords:
            if keyword in message:
                framework_score += 2
        
        # Exclude non-security commits
        exclude_terms = [
            'merge', 'revert', 'format', 'style', 'refactor', 
            'test', 'doc', 'comment', 'typo', 'whitespace'
        ]
        
        if any(term in message for term in exclude_terms):
            framework_score = max(0, framework_score - 2)
        
        return framework_score >= 2
    
    def get_framework_category(self, repo_name: str) -> str:
        """Get the framework category for a repository"""
        for category, config in self.framework_ecosystem.items():
            if repo_name in config['repositories']:
                return category
        return 'unknown'
    
    def collect_framework_commits_with_diffs(self, commits: List[Dict]) -> List[Dict]:
        """Collect detailed commit information with diffs"""
        detailed_commits = []
        
        for i, commit in enumerate(commits):
            if i % 10 == 0:
                logger.info(f"Processing commit diffs {i+1}/{len(commits)}")
            
            try:
                repo_name = commit['repository']
                commit_sha = commit['sha']
                
                # Get commit details with diff
                url = f"{self.base_url}/repos/{repo_name}/commits/{commit_sha}"
                response = requests.get(url, headers=self.headers)
                
                if response.status_code == 200:
                    commit_data = response.json()
                    
                    # Filter for Java files with security-relevant changes
                    java_files = []
                    framework_category = commit.get('framework_category', 'unknown')
                    framework_config = self.framework_ecosystem.get(framework_category, {})
                    
                    for file_info in commit_data.get('files', []):
                        filename = file_info.get('filename', '')
                        patch = file_info.get('patch', '')
                        
                        if filename.endswith('.java') and patch:
                            # Check if patch contains framework-relevant security patterns
                            if self.has_security_patterns(patch, framework_config):
                                java_files.append({
                                    'filename': filename,
                                    'status': file_info.get('status'),
                                    'additions': file_info.get('additions', 0),
                                    'deletions': file_info.get('deletions', 0),
                                    'patch': patch,
                                    'raw_url': file_info.get('raw_url')
                                })
                    
                    if java_files:
                        detailed_commit = {
                            'sha': commit_sha,
                            'message': commit_data['commit']['message'],
                            'author': commit_data['commit']['author'],
                            'date': commit_data['commit']['author']['date'],
                            'repository': repo_name,
                            'java_files': java_files,
                            'stats': commit_data.get('stats', {}),
                            'url': commit_data.get('html_url'),
                            'framework_category': framework_category,
                            'collection_strategy': 'framework_systematic',
                            'query_matched': commit.get('query_matched'),
                            'time_period': commit.get('time_period')
                        }
                        
                        detailed_commits.append(detailed_commit)
                
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Error processing commit {commit.get('sha', 'unknown')}: {e}")
                continue
        
        return detailed_commits
    
    def has_security_patterns(self, patch: str, framework_config: Dict) -> bool:
        """Check if patch contains security-relevant patterns for the framework"""
        if not framework_config:
            return True  # Default to include if no config
        
        patch_lower = patch.lower()
        
        # Check for framework-specific code patterns
        pattern_score = 0
        for pattern in framework_config.get('code_patterns', []):
            if pattern.lower() in patch_lower:
                pattern_score += 1
        
        # Check for security indicators
        security_indicators = [
            'sanitize', 'validate', 'escape', 'encode', 'whitelist',
            'blacklist', 'filter', 'check', 'verify', 'secure'
        ]
        
        security_score = sum(1 for indicator in security_indicators 
                           if indicator in patch_lower)
        
        # Check for vulnerability-specific patterns
        vuln_patterns = {
            'sql_injection': ['preparestatement', 'setstring', 'setparameter'],
            'xss': ['escapehtml', 'htmlencode', 'sanitize'],
            'command_injection': ['processbuilder', 'runtime.exec'],
            'deserialization': ['objectinputstream', 'readobject', 'whitelist'],
            'path_traversal': ['getcanonicalpath', 'normalize'],
            'xxe': ['setfeature', 'secure_processing']
        }
        
        vuln_score = 0
        for vuln_type in framework_config.get('vulnerability_focus', []):
            if vuln_type in vuln_patterns:
                patterns = vuln_patterns[vuln_type]
                vuln_score += sum(1 for pattern in patterns if pattern in patch_lower)
        
        # Require some evidence of security-related changes
        return (pattern_score + security_score + vuln_score) >= 2
    
    def run_systematic_framework_collection(self, output_file: str = 'framework_systematic_commits.json'):
        """Run systematic collection across all frameworks"""
        logger.info("Starting systematic framework collection...")
        
        all_commits = []
        collection_stats = {
            'framework_breakdown': {},
            'time_period_breakdown': {},
            'vulnerability_focus_breakdown': {},
            'total_repositories_processed': 0,
            'total_commits_found': 0
        }
        
        # Process each framework ecosystem
        for framework_name, framework_config in self.framework_ecosystem.items():
            logger.info(f"Processing framework ecosystem: {framework_name}")
            
            framework_commits = []
            
            # Process each repository in the framework
            for repo_name in framework_config['repositories']:
                logger.info(f"  Processing repository: {repo_name}")
                
                # Get repository security profile
                security_profile = self.get_repository_security_profile(repo_name)
                if not security_profile:
                    logger.warning(f"Could not get security profile for {repo_name}")
                    continue
                
                collection_stats['total_repositories_processed'] += 1
                
                # Collect commits across different time periods
                repo_commits = []
                
                # Recent commits (higher priority)
                recent_commits = self.search_framework_security_commits(
                    framework_config, repo_name, 
                    time_period=('2023-01-01', '2024-12-31', 'recent'),
                    max_commits=25
                )
                repo_commits.extend(recent_commits)
                
                # Historical commits (if needed)
                if len(recent_commits) < 15:  # If not enough recent commits
                    historical_commits = self.search_framework_security_commits(
                        framework_config, repo_name,
                        time_period=('2020-01-01', '2022-12-31', 'historical'),
                        max_commits=15
                    )
                    repo_commits.extend(historical_commits)
                
                # Add repository security profile to commits
                for commit in repo_commits:
                    commit['repository_security_profile'] = security_profile
                
                framework_commits.extend(repo_commits)
                time.sleep(2)  # Rate limiting between repositories
            
            # Get detailed commit information with diffs
            logger.info(f"Getting detailed commit information for {framework_name}")
            detailed_commits = self.collect_framework_commits_with_diffs(framework_commits)
            
            all_commits.extend(detailed_commits)
            
            # Update statistics
            collection_stats['framework_breakdown'][framework_name] = {
                'repositories_processed': len(framework_config['repositories']),
                'commits_found': len(detailed_commits),
                'vulnerability_focus': framework_config['vulnerability_focus']
            }
            
            # Track by vulnerability focus
            for vuln_type in framework_config['vulnerability_focus']:
                if vuln_type not in collection_stats['vulnerability_focus_breakdown']:
                    collection_stats['vulnerability_focus_breakdown'][vuln_type] = 0
                collection_stats['vulnerability_focus_breakdown'][vuln_type] += len(detailed_commits)
            
            logger.info(f"Completed {framework_name}: {len(detailed_commits)} commits")
        
        # Remove duplicates based on SHA
        unique_commits = []
        seen_shas = set()
        
        for commit in all_commits:
            sha = commit['sha']
            if sha not in seen_shas:
                unique_commits.append(commit)
                seen_shas.add(sha)
        
        collection_stats['total_commits_found'] = len(unique_commits)
        collection_stats['duplicates_removed'] = len(all_commits) - len(unique_commits)
        
        # Save results
        logger.info(f"Saving {len(unique_commits)} unique commits to {output_file}")
        with open(output_file, 'w') as f:
            json.dump(unique_commits, f, indent=2)
        
        # Save collection statistics
        stats_file = output_file.replace('.json', '_stats.json')
        with open(stats_file, 'w') as f:
            json.dump(collection_stats, f, indent=2)
        
        # Generate collection report
        self.generate_framework_collection_report(unique_commits, collection_stats, output_file)
        
        return unique_commits
    
    def generate_framework_collection_report(self, commits: List[Dict], 
                                           stats: Dict, output_file: str):
        """Generate comprehensive collection report"""
        
        report = {
            'collection_timestamp': datetime.now().isoformat(),
            'collection_strategy': 'framework_systematic',
            'summary': {
                'total_commits': len(commits),
                'total_repositories': stats['total_repositories_processed'],
                'framework_ecosystems': len(self.framework_ecosystem),
                'duplicates_removed': stats['duplicates_removed']
            },
            'framework_breakdown': stats['framework_breakdown'],
            'vulnerability_focus_effectiveness': {},
            'time_distribution': {},
            'repository_effectiveness': {},
            'quality_indicators': {}
        }
        
        # Analyze time distribution
        time_counts = {}
        for commit in commits:
            date = commit.get('date', '')
            if date:
                year = date[:4]
                time_counts[year] = time_counts.get(year, 0) + 1
        report['time_distribution'] = time_counts
        
        # Analyze repository effectiveness
        repo_counts = {}
        for commit in commits:
            repo = commit.get('repository', 'unknown')
            repo_counts[repo] = repo_counts.get(repo, 0) + 1
        
        # Sort by effectiveness
        report['repository_effectiveness'] = dict(
            sorted(repo_counts.items(), key=lambda x: x[1], reverse=True)
        )
        
        # Analyze vulnerability focus effectiveness
        for vuln_type, count in stats['vulnerability_focus_breakdown'].items():
            effectiveness = count / stats['total_repositories_processed']
            report['vulnerability_focus_effectiveness'][vuln_type] = {
                'total_commits': count,
                'commits_per_repository': round(effectiveness, 2)
            }
        
        # Quality indicators
        commits_with_profiles = len([c for c in commits if 'repository_security_profile' in c])
        commits_with_time_period = len([c for c in commits if 'time_period' in c])
        
        report['quality_indicators'] = {
            'commits_with_security_profiles': commits_with_profiles,
            'commits_with_time_classification': commits_with_time_period,
            'average_java_files_per_commit': sum(len(c.get('java_files', [])) for c in commits) / len(commits) if commits else 0,
            'frameworks_with_commits': len([f for f, data in stats['framework_breakdown'].items() if data['commits_found'] > 0])
        }
        
        # Save report
        report_file = output_file.replace('.json', '_collection_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n" + "="*70)
        print("🏗️ FRAMEWORK SYSTEMATIC COLLECTION REPORT")
        print("="*70)
        print(f"📊 Total commits collected: {len(commits)}")
        print(f"🏢 Repositories processed: {stats['total_repositories_processed']}")
        print(f"🔧 Framework ecosystems: {len(self.framework_ecosystem)}")
        
        print(f"\n📋 Framework breakdown:")
        for framework, data in stats['framework_breakdown'].items():
            print(f"  {framework}: {data['commits_found']} commits from {data['repositories_processed']} repos")
        
        print(f"\n🎯 Vulnerability focus effectiveness:")
        for vuln_type, data in report['vulnerability_focus_effectiveness'].items():
            print(f"  {vuln_type}: {data['total_commits']} commits ({data['commits_per_repository']} per repo)")
        
        print(f"\n🏆 Top repositories:")
        for repo, count in list(report['repository_effectiveness'].items())[:5]:
            print(f"  {repo}: {count} commits")
        
        print(f"\n📁 Files created:")
        print(f"  📊 Commits: {output_file}")
        print(f"  📈 Statistics: {stats_file}")
        print(f"  📋 Report: {report_file}")
        print("="*70)

# Example usage
if __name__ == "__main__":
    # Load GitHub token
    try:
        with open('github_token.txt', 'r') as f:
            token = f.read().strip()
    except FileNotFoundError:
        print("Please create github_token.txt with your GitHub token")
        exit(1)
    
    collector = FrameworkSystematicCollector(token)
    commits = collector.run_systematic_framework_collection()
    
    print(f"\nFramework systematic collection complete! Collected {len(commits)} commits")