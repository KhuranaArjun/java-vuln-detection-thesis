#!/usr/bin/env python3
"""
Comprehensive Java Vulnerability Commit Collection Pipeline
Systematically collect, validate, and refine the 270+ identified commits
Build the definitive dataset once - no tracking back needed
"""

import requests
import json
import re
import time
import csv
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityCommit:
    """Complete vulnerability commit data structure"""
    repo: str
    commit_sha: str
    cve_id: str
    commit_url: str
    commit_message: str
    author: str
    date: str
    owasp_category: str
    vulnerability_type: str
    priority_tier: int
    java_files_count: int
    lines_added: int
    lines_deleted: int
    has_vulnerable_code: bool
    quality_score: float
    java_files: List[Dict]
    source_category: str
    verification_status: str

class ComprehensiveJavaVulnCollector:
    """
    Systematic collection of Java vulnerability commits based on research plan
    Focus: Get comprehensive, high-quality dataset in one systematic sweep
    """
    
    def __init__(self, github_token: str):
        self.github_token = github_token
        self.headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        # Collection tracking
        self.collected_commits: List[VulnerabilityCommit] = []
        self.failed_commits: List[Dict] = []
        self.duplicate_commits: Set[str] = set()
        
        # Collection statistics
        self.stats = {
            'total_attempted': 0,
            'successfully_collected': 0,
            'validation_passed': 0,
            'duplicates_removed': 0,
            'api_failures': 0
        }

    def get_priority_tier_1_targets(self) -> List[Dict]:
        """
        Tier 1: Critical, universal applicability vulnerabilities
        Must collect these for dataset completeness
        """
        return [
            # Log4Shell Series - Most critical Java vulnerability ever
            {
                'repo': 'apache/logging-log4j2',
                'search_terms': ['CVE-2021-44228', 'JNDI', 'lookup', 'Log4Shell'],
                'cve_list': ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105'],
                'date_range': ('2021-11-01', '2022-02-01'),
                'commits_expected': 15,
                'owasp_category': 'A03_Injection',
                'vulnerability_type': 'JNDI_Injection',
                'priority': 1
            },
            
            # Spring4Shell - Framework RCE 
            {
                'repo': 'spring-projects/spring-framework',
                'search_terms': ['CVE-2022-22965', 'Spring4Shell', 'WebDataBinder', 'ClassLoader'],
                'cve_list': ['CVE-2022-22965', 'CVE-2022-22968'],
                'date_range': ('2022-03-01', '2022-05-01'),
                'commits_expected': 8,
                'owasp_category': 'A03_Injection',
                'vulnerability_type': 'Expression_Language_Injection',
                'priority': 1
            },
            
            # Jackson Deserialization - Universal JSON vulnerability
            {
                'repo': 'FasterXML/jackson-databind',
                'search_terms': ['CVE-2017-7525', 'deserialization', 'polymorphic', 'gadget'],
                'cve_list': ['CVE-2017-7525', 'CVE-2018-7489', 'CVE-2019-12086'],
                'date_range': ('2017-01-01', '2023-12-31'),
                'commits_expected': 25,
                'owasp_category': 'A08_Software_Data_Integrity',
                'vulnerability_type': 'Unsafe_Deserialization',
                'priority': 1
            },
            
            # Apache Struts - Historic RCE series
            {
                'repo': 'apache/struts',
                'search_terms': ['CVE-2023-50164', 'CVE-2017-5638', 'RCE', 'file upload'],
                'cve_list': ['CVE-2023-50164', 'CVE-2017-5638', 'CVE-2017-9791'],
                'date_range': ('2017-01-01', '2024-12-31'),
                'commits_expected': 12,
                'owasp_category': 'A01_Broken_Access_Control',
                'vulnerability_type': 'Path_Traversal',
                'priority': 1
            }
        ]

    def get_priority_tier_2_targets(self) -> List[Dict]:
        """
        Tier 2: Comprehensive framework coverage
        Important for dataset diversity and completeness
        """
        return [
            # Apache Tomcat - Enterprise application server
            {
                'repo': 'apache/tomcat',
                'search_terms': ['security', 'vulnerability', 'CVE', 'fix'],
                'cve_list': ['CVE-2024-50379', 'CVE-2023-45648', 'CVE-2023-44487'],
                'date_range': ('2020-01-01', '2024-12-31'),
                'commits_expected': 20,
                'owasp_category': 'A04_Insecure_Design',
                'vulnerability_type': 'Race_Condition',
                'priority': 2
            },
            
            # Spring Security - Authentication/Authorization
            {
                'repo': 'spring-projects/spring-security',
                'search_terms': ['CVE', 'security', 'authorization', 'bypass'],
                'cve_list': ['CVE-2025-41232', 'CVE-2023-34035'],
                'date_range': ('2020-01-01', '2024-12-31'),
                'commits_expected': 15,
                'owasp_category': 'A01_Broken_Access_Control',
                'vulnerability_type': 'Authorization_Bypass',
                'priority': 2
            },
            
            # Apache Kafka - Message broker vulnerabilities
            {
                'repo': 'apache/kafka',
                'search_terms': ['CVE', 'security', 'SASL', 'JNDI'],
                'cve_list': ['CVE-2025-27819', 'CVE-2025-27818', 'CVE-2023-25194'],
                'date_range': ('2020-01-01', '2024-12-31'),
                'commits_expected': 10,
                'owasp_category': 'A03_Injection',
                'vulnerability_type': 'JNDI_Injection',
                'priority': 2
            },
            
            # Hibernate ORM - Database layer security
            {
                'repo': 'hibernate/hibernate-orm',
                'search_terms': ['CVE', 'SQL injection', 'HQL', 'criteria'],
                'cve_list': ['CVE-2020-25638'],
                'date_range': ('2019-01-01', '2024-12-31'),
                'commits_expected': 8,
                'owasp_category': 'A03_Injection',
                'vulnerability_type': 'SQL_Injection',
                'priority': 2
            },
            
            # Apache Shiro - Security framework
            {
                'repo': 'apache/shiro',
                'search_terms': ['CVE', 'authentication', 'bypass', 'path traversal'],
                'cve_list': ['CVE-2023-34478', 'CVE-2023-22602'],
                'date_range': ('2019-01-01', '2024-12-31'),
                'commits_expected': 12,
                'owasp_category': 'A01_Broken_Access_Control',
                'vulnerability_type': 'Authentication_Bypass',
                'priority': 2
            }
        ]

    def get_priority_tier_3_targets(self) -> List[Dict]:
        """
        Tier 3: Extended coverage for completeness
        Fill gaps and ensure comprehensive vulnerability type coverage
        """
        return [
            # Netty - Network application framework
            {
                'repo': 'netty/netty',
                'search_terms': ['CVE', 'security', 'TLS', 'hostname'],
                'cve_list': ['CVE-2023-4586', 'CVE-2024-47535'],
                'date_range': ('2020-01-01', '2024-12-31'),
                'commits_expected': 8,
                'owasp_category': 'A02_Cryptographic_Failures',
                'vulnerability_type': 'TLS_Validation',
                'priority': 3
            },
            
            # Apache Commons - Utility libraries
            {
                'repo': 'apache/commons-collections',
                'search_terms': ['CVE-2015-7501', 'deserialization', 'gadget'],
                'cve_list': ['CVE-2015-7501'],
                'date_range': ('2015-01-01', '2020-12-31'),
                'commits_expected': 5,
                'owasp_category': 'A08_Software_Data_Integrity',
                'vulnerability_type': 'Unsafe_Deserialization',
                'priority': 3
            },
            
            # Maven - Build tool security
            {
                'repo': 'apache/maven',
                'search_terms': ['CVE', 'security', 'xml', 'dependency'],
                'cve_list': ['CVE-2021-26291'],
                'date_range': ('2020-01-01', '2024-12-31'),
                'commits_expected': 6,
                'owasp_category': 'A06_Vulnerable_Components',
                'vulnerability_type': 'Dependency_Confusion',
                'priority': 3
            }
        ]

    def search_commits_for_target(self, target: Dict) -> List[Dict]:
        """
        Search for commits in a specific repository using multiple strategies
        """
        repo = target['repo']
        logger.info(f"🔍 Searching commits in {repo}...")
        
        all_commits = []
        
        # Strategy 1: Search by commit messages containing CVE/security terms
        for search_term in target['search_terms']:
            commits = self.search_commits_by_message(repo, search_term, 
                                                   target['date_range'])
            all_commits.extend(commits)
        
        # Strategy 2: Search for specific CVE references
        for cve in target['cve_list']:
            commits = self.search_commits_by_message(repo, cve, 
                                                   target['date_range'])
            all_commits.extend(commits)
        
        # Strategy 3: Search security-related file changes
        security_paths = ['security', 'auth', 'filter', 'validation']
        for path in security_paths:
            commits = self.search_commits_by_path(repo, path, 
                                                target['date_range'])
            all_commits.extend(commits)
        
        # Remove duplicates and add metadata
        unique_commits = self.deduplicate_commits(all_commits)
        
        # Add target metadata to commits
        for commit in unique_commits:
            commit.update({
                'source_repo': repo,
                'source_category': f"Tier_{target['priority']}",
                'owasp_category': target['owasp_category'],
                'vulnerability_type': target['vulnerability_type'],
                'priority_tier': target['priority'],
                'expected_from_target': target['commits_expected']
            })
        
        logger.info(f"✅ Found {len(unique_commits)} unique commits in {repo}")
        return unique_commits

    def search_commits_by_message(self, repo: str, query: str, 
                                 date_range: Tuple[str, str]) -> List[Dict]:
        """
        Search commits by message content using GitHub API
        """
        since_date, until_date = date_range
        url = f"https://api.github.com/repos/{repo}/commits"
        
        params = {
            'since': f"{since_date}T00:00:00Z",
            'until': f"{until_date}T23:59:59Z",
            'per_page': 100
        }
        
        commits = []
        page = 1
        
        try:
            while page <= 5:  # Limit to 5 pages per search
                params['page'] = page
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
                
                if response.status_code != 200:
                    logger.warning(f"API error {response.status_code} for {repo}")
                    break
                
                page_commits = response.json()
                if not page_commits:
                    break
                
                # Filter commits by message content
                for commit in page_commits:
                    message = commit.get('commit', {}).get('message', '').lower()
                    if query.lower() in message:
                        commits.append({
                            'sha': commit['sha'],
                            'message': commit['commit']['message'],
                            'author': commit['commit']['author']['name'],
                            'date': commit['commit']['author']['date'],
                            'url': commit['html_url']
                        })
                
                page += 1
                time.sleep(1)  # Rate limiting
                
        except requests.RequestException as e:
            logger.error(f"Request failed for {repo}: {e}")
        
        return commits

    def search_commits_by_path(self, repo: str, path: str, 
                             date_range: Tuple[str, str]) -> List[Dict]:
        """
        Search commits that modified files in specific security-related paths
        """
        since_date, until_date = date_range
        url = f"https://api.github.com/repos/{repo}/commits"
        
        params = {
            'path': path,
            'since': f"{since_date}T00:00:00Z",
            'until': f"{until_date}T23:59:59Z",
            'per_page': 50
        }
        
        commits = []
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            
            if response.status_code == 200:
                page_commits = response.json()
                for commit in page_commits:
                    commits.append({
                        'sha': commit['sha'],
                        'message': commit['commit']['message'],
                        'author': commit['commit']['author']['name'],
                        'date': commit['commit']['author']['date'],
                        'url': commit['html_url']
                    })
            
            time.sleep(1)  # Rate limiting
            
        except requests.RequestException as e:
            logger.error(f"Path search failed for {repo}/{path}: {e}")
        
        return commits

    def deduplicate_commits(self, commits: List[Dict]) -> List[Dict]:
        """
        Remove duplicate commits based on SHA
        """
        seen_shas = set()
        unique_commits = []
        
        for commit in commits:
            sha = commit['sha']
            if sha not in seen_shas:
                seen_shas.add(sha)
                unique_commits.append(commit)
            else:
                self.stats['duplicates_removed'] += 1
        
        return unique_commits

    def validate_and_analyze_commit(self, commit_info: Dict) -> Optional[VulnerabilityCommit]:
        """
        Comprehensive validation and analysis of a single commit
        """
        repo = commit_info['source_repo']
        commit_sha = commit_info['sha']
        
        # Fetch detailed commit data
        commit_data = self.fetch_detailed_commit(repo, commit_sha)
        if not commit_data:
            self.failed_commits.append({
                'repo': repo, 
                'sha': commit_sha, 
                'reason': 'API_fetch_failed'
            })
            self.stats['api_failures'] += 1
            return None
        
        # Analyze Java files in the commit
        java_analysis = self.analyze_java_files(commit_data.get('files', []))
        
        # Check if commit has vulnerable code patterns
        has_vulnerable_code = self.detect_vulnerable_patterns(java_analysis['java_files'])
        
        # Calculate quality score
        quality_score = self.calculate_commit_quality_score(
            java_analysis, commit_data['commit']['message'], has_vulnerable_code
        )
        
        # Skip low-quality commits
        if quality_score < 0.3:
            logger.debug(f"Skipping low-quality commit {repo}/{commit_sha[:8]} (score: {quality_score:.2f})")
            return None
        
        # Create VulnerabilityCommit object
        vuln_commit = VulnerabilityCommit(
            repo=repo,
            commit_sha=commit_sha,
            cve_id=self.extract_cve_from_message(commit_data['commit']['message']),
            commit_url=commit_data['html_url'],
            commit_message=commit_data['commit']['message'],
            author=commit_data['commit']['author']['name'],
            date=commit_data['commit']['author']['date'],
            owasp_category=commit_info['owasp_category'],
            vulnerability_type=commit_info['vulnerability_type'],
            priority_tier=commit_info['priority_tier'],
            java_files_count=java_analysis['java_files_count'],
            lines_added=java_analysis['total_additions'],
            lines_deleted=java_analysis['total_deletions'],
            has_vulnerable_code=has_vulnerable_code,
            quality_score=quality_score,
            java_files=java_analysis['java_files'],
            source_category=commit_info['source_category'],
            verification_status='validated'
        )
        
        self.stats['validation_passed'] += 1
        return vuln_commit

    def fetch_detailed_commit(self, repo: str, commit_sha: str) -> Optional[Dict]:
        """
        Fetch detailed commit information from GitHub API
        """
        url = f"https://api.github.com/repos/{repo}/commits/{commit_sha}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to fetch {repo}/{commit_sha}: {response.status_code}")
                return None
        except requests.RequestException as e:
            logger.error(f"Request failed for {repo}/{commit_sha}: {e}")
            return None

    def analyze_java_files(self, files: List[Dict]) -> Dict:
        """
        Analyze Java files in the commit for vulnerability patterns
        """
        java_files = []
        total_additions = 0
        total_deletions = 0
        
        for file in files:
            filename = file['filename']
            if filename.endswith(('.java', '.kt', '.scala')):
                java_file_analysis = {
                    'filename': filename,
                    'additions': file.get('additions', 0),
                    'deletions': file.get('deletions', 0),
                    'patch': file.get('patch', ''),
                    'has_security_patterns': self.has_security_patterns(file.get('patch', ''))
                }
                java_files.append(java_file_analysis)
                total_additions += java_file_analysis['additions']
                total_deletions += java_file_analysis['deletions']
        
        return {
            'java_files': java_files,
            'java_files_count': len(java_files),
            'total_additions': total_additions,
            'total_deletions': total_deletions
        }

    def has_security_patterns(self, patch: str) -> bool:
        """
        Check if patch contains security-related patterns
        """
        security_patterns = [
            r'\b(validate|sanitize|escape|filter|secure|authorize|authenticate)\s*\(',
            r'(checkAccess|checkPermission|isAuthorized|hasRole)',
            r'(JNDI|lookup|deserialize|eval|exec|getClassLoader)',
            r'setDisallowedFields|setAllowedFields|WebDataBinder',
            r'(PreparedStatement|parameterized|sql.*injection)',
            r'@(Secured|PreAuthorize|PostAuthorize|RolesAllowed)',
        ]
        
        for pattern in security_patterns:
            if re.search(pattern, patch, re.IGNORECASE):
                return True
        return False

    def detect_vulnerable_patterns(self, java_files: List[Dict]) -> bool:
        """
        Detect if commit contains actual vulnerable code patterns
        """
        for java_file in java_files:
            patch = java_file['patch']
            
            # Look for removed lines (vulnerable code) and added lines (fixes)
            removed_lines = [line for line in patch.split('\n') 
                           if line.startswith('-') and not line.startswith('---')]
            added_lines = [line for line in patch.split('\n') 
                         if line.startswith('+') and not line.startswith('+++')]
            
            # Must have both vulnerable code removal and fixes
            if len(removed_lines) >= 2 and len(added_lines) >= 2:
                # Check for vulnerability indicators in removed code
                removed_text = ' '.join(removed_lines)
                if any(pattern in removed_text.lower() for pattern in 
                      ['vulnerable', 'unsafe', 'exploit', 'attack', 'malicious']):
                    return True
                
                # Check for security fixes in added code
                added_text = ' '.join(added_lines)
                if any(pattern in added_text.lower() for pattern in 
                      ['validate', 'sanitize', 'secure', 'fix', 'prevent']):
                    return True
        
        return False

    def calculate_commit_quality_score(self, java_analysis: Dict, 
                                     commit_message: str, has_vulnerable_code: bool) -> float:
        """
        Calculate comprehensive quality score for the commit
        """
        score = 0.0
        
        # Java files presence (0-0.25)
        if java_analysis['java_files_count'] > 0:
            score += 0.25 * min(java_analysis['java_files_count'] / 3, 1)
        
        # Code change volume (0-0.2)
        total_changes = java_analysis['total_additions'] + java_analysis['total_deletions']
        if total_changes > 0:
            score += 0.2 * min(total_changes / 50, 1)
        
        # Security patterns in files (0-0.25)
        security_files = sum(1 for f in java_analysis['java_files'] if f['has_security_patterns'])
        if security_files > 0:
            score += 0.25 * min(security_files / 2, 1)
        
        # Vulnerable code detection (0-0.2)
        if has_vulnerable_code:
            score += 0.2
        
        # Commit message quality (0-0.1)
        security_keywords = ['cve', 'security', 'vulnerability', 'fix', 'exploit', 'injection']
        message_lower = commit_message.lower()
        keyword_matches = sum(1 for keyword in security_keywords if keyword in message_lower)
        if keyword_matches > 0:
            score += 0.1 * min(keyword_matches / 3, 1)
        
        return min(score, 1.0)

    def extract_cve_from_message(self, message: str) -> str:
        """
        Extract CVE identifier from commit message
        """
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        match = re.search(cve_pattern, message, re.IGNORECASE)
        return match.group(0) if match else 'Unknown'

    def run_comprehensive_collection(self) -> Dict:
        """
        Run the complete collection pipeline for all priority tiers
        """
        logger.info("🚀 STARTING COMPREHENSIVE JAVA VULNERABILITY COLLECTION")
        logger.info("="*80)
        
        start_time = datetime.now()
        
        # Collect from all priority tiers
        all_targets = (self.get_priority_tier_1_targets() + 
                      self.get_priority_tier_2_targets() + 
                      self.get_priority_tier_3_targets())
        
        logger.info(f"📋 Targeting {len(all_targets)} repositories across 3 priority tiers")
        
        # Phase 1: Search and collect commit candidates
        logger.info("\n🔍 PHASE 1: Searching for vulnerability commits...")
        all_commit_candidates = []
        
        for i, target in enumerate(all_targets, 1):
            logger.info(f"[{i:2d}/{len(all_targets)}] Processing {target['repo']}...")
            commits = self.search_commits_for_target(target)
            all_commit_candidates.extend(commits)
            self.stats['total_attempted'] += len(commits)
            time.sleep(2)  # Rate limiting between repositories
        
        logger.info(f"✅ Phase 1 complete: {len(all_commit_candidates)} commit candidates found")
        
        # Phase 2: Validate and analyze commits
        logger.info("\n🔬 PHASE 2: Validating and analyzing commits...")
        
        validated_commits = []
        batch_size = 10
        
        for i in range(0, len(all_commit_candidates), batch_size):
            batch = all_commit_candidates[i:i+batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}/{(len(all_commit_candidates)-1)//batch_size + 1}")
            
            for commit_info in batch:
                validated_commit = self.validate_and_analyze_commit(commit_info)
                if validated_commit:
                    validated_commits.append(validated_commit)
                    self.stats['successfully_collected'] += 1
                
                time.sleep(1)  # Rate limiting
        
        self.collected_commits = validated_commits
        
        # Phase 3: Quality analysis and reporting
        logger.info("\n📊 PHASE 3: Quality analysis and final processing...")
        results = self.generate_final_results()
        
        end_time = datetime.now()
        duration = end_time - start_time
        
        logger.info(f"\n✅ COLLECTION COMPLETE!")
        logger.info(f"⏱️  Total time: {duration}")
        logger.info(f"📈 Final results: {results['summary']}")
        
        return results

    def generate_final_results(self) -> Dict:
        """
        Generate comprehensive final results and statistics
        """
        total_commits = len(self.collected_commits)
        
        # Quality distribution
        high_quality = len([c for c in self.collected_commits if c.quality_score >= 0.7])
        medium_quality = len([c for c in self.collected_commits if 0.4 <= c.quality_score < 0.7])
        low_quality = len([c for c in self.collected_commits if c.quality_score < 0.4])
        
        # Vulnerability type distribution
        vuln_types = {}
        for commit in self.collected_commits:
            vtype = commit.vulnerability_type
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        
        # Priority tier distribution
        tier_distribution = {1: 0, 2: 0, 3: 0}
        for commit in self.collected_commits:
            tier_distribution[commit.priority_tier] += 1
        
        # Repository coverage
        repo_coverage = {}
        for commit in self.collected_commits:
            repo = commit.repo
            repo_coverage[repo] = repo_coverage.get(repo, 0) + 1
        
        results = {
            'collection_timestamp': datetime.now().isoformat(),
            'total_commits_collected': total_commits,
            'statistics': self.stats,
            'quality_distribution': {
                'high_quality': high_quality,
                'medium_quality': medium_quality,
                'low_quality': low_quality,
                'average_quality_score': sum(c.quality_score for c in self.collected_commits) / total_commits if total_commits > 0 else 0
            },
            'vulnerability_type_distribution': vuln_types,
            'priority_tier_distribution': tier_distribution,
            'repository_coverage': repo_coverage,
            'commits': [asdict(commit) for commit in self.collected_commits],
            'failed_commits': self.failed_commits,
            'summary': {
                'ready_for_wartschinski': total_commits >= 100,
                'recommended_action': self.get_recommendation(total_commits, high_quality),
                'dataset_quality': 'High' if high_quality/total_commits > 0.6 else 'Medium' if high_quality/total_commits > 0.3 else 'Low' if total_commits > 0 else 'None'
            }
        }
        
        return results

    def get_recommendation(self, total_commits: int, high_quality: int) -> str:
        """
        Generate actionable recommendation based on collection results
        """
        if total_commits == 0:
            return "Use MoreFixes dataset (11,232 samples) - no commits collected"
        elif total_commits < 50:
            return f"Insufficient commits ({total_commits}). Combine with MoreFixes dataset"
        elif high_quality / total_commits > 0.6:
            return f"Excellent collection ({total_commits} commits, {high_quality} high-quality). Proceed with Wartschinski pipeline"
        elif high_quality / total_commits > 0.3:
            return f"Good collection ({total_commits} commits). Filter for high-quality only or combine with MoreFixes"
        else:
            return f"Low quality collection. Use MoreFixes dataset instead"

    def save_comprehensive_dataset(self, results: Dict, output_dir: str):
        """
        Save complete dataset with multiple formats for different use cases
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 1. Complete JSON dataset (for processing)
        json_file = output_path / f"java_vulnerability_commits_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"💾 Complete dataset saved: {json_file}")
        
        # 2. CSV summary (for analysis)
        csv_file = output_path / f"vulnerability_commits_summary_{timestamp}.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'repo', 'commit_sha', 'cve_id', 'date', 'vulnerability_type',
                'owasp_category', 'priority_tier', 'quality_score', 'java_files_count',
                'lines_added', 'lines_deleted', 'has_vulnerable_code', 'commit_message'
            ])
            
            for commit_dict in results['commits']:
                writer.writerow([
                    commit_dict['repo'],
                    commit_dict['commit_sha'],
                    commit_dict['cve_id'],
                    commit_dict['date'],
                    commit_dict['vulnerability_type'],
                    commit_dict['owasp_category'],
                    commit_dict['priority_tier'],
                    commit_dict['quality_score'],
                    commit_dict['java_files_count'],
                    commit_dict['lines_added'],
                    commit_dict['lines_deleted'],
                    commit_dict['has_vulnerable_code'],
                    commit_dict['commit_message'][:100] + '...' if len(commit_dict['commit_message']) > 100 else commit_dict['commit_message']
                ])
        logger.info(f"📊 CSV summary saved: {csv_file}")
        
        # 3. High-quality commits only (for Wartschinski pipeline)
        high_quality_commits = [c for c in results['commits'] if c['quality_score'] >= 0.7]
        hq_file = output_path / f"high_quality_commits_{timestamp}.json"
        with open(hq_file, 'w') as f:
            json.dump({
                'metadata': {
                    'collection_date': results['collection_timestamp'],
                    'total_high_quality': len(high_quality_commits),
                    'quality_threshold': 0.7,
                    'ready_for_wartschinski': len(high_quality_commits) >= 50
                },
                'commits': high_quality_commits
            }, f, indent=2, default=str)
        logger.info(f"⭐ High-quality commits saved: {hq_file}")
        
        # 4. Statistics report
        stats_file = output_path / f"collection_statistics_{timestamp}.txt"
        with open(stats_file, 'w') as f:
            f.write("JAVA VULNERABILITY COMMIT COLLECTION REPORT\n")
            f.write("="*50 + "\n\n")
            
            f.write(f"Collection Date: {results['collection_timestamp']}\n")
            f.write(f"Total Commits Collected: {results['total_commits_collected']}\n")
            f.write(f"Collection Success Rate: {(results['statistics']['successfully_collected']/results['statistics']['total_attempted']*100):.1f}%\n\n")
            
            f.write("QUALITY DISTRIBUTION:\n")
            f.write(f"High Quality (≥0.7): {results['quality_distribution']['high_quality']} ({(results['quality_distribution']['high_quality']/results['total_commits_collected']*100):.1f}%)\n")
            f.write(f"Medium Quality (0.4-0.7): {results['quality_distribution']['medium_quality']} ({(results['quality_distribution']['medium_quality']/results['total_commits_collected']*100):.1f}%)\n")
            f.write(f"Low Quality (<0.4): {results['quality_distribution']['low_quality']} ({(results['quality_distribution']['low_quality']/results['total_commits_collected']*100):.1f}%)\n")
            f.write(f"Average Quality Score: {results['quality_distribution']['average_quality_score']:.3f}\n\n")
            
            f.write("VULNERABILITY TYPE COVERAGE:\n")
            for vtype, count in sorted(results['vulnerability_type_distribution'].items()):
                f.write(f"{vtype}: {count} commits\n")
            
            f.write(f"\nREPOSITORY COVERAGE:\n")
            for repo, count in sorted(results['repository_coverage'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"{repo}: {count} commits\n")
            
            f.write(f"\nRECOMMENDATION:\n")
            f.write(f"{results['summary']['recommended_action']}\n")
        
        logger.info(f"📋 Statistics report saved: {stats_file}")
        
        # 5. Wartschinski-ready format (if sufficient quality)
        if results['summary']['ready_for_wartschinski']:
            wartschinski_file = output_path / f"wartschinski_ready_commits_{timestamp}.json"
            wartschinski_data = {
                'methodology': 'Enhanced Wartschinski VUDENC Pipeline',
                'collection_metadata': {
                    'total_commits': len(high_quality_commits),
                    'quality_threshold': 0.7,
                    'vulnerability_types_covered': len(results['vulnerability_type_distribution']),
                    'owasp_categories_covered': len(set(c['owasp_category'] for c in high_quality_commits))
                },
                'commits_for_processing': [
                    {
                        'repo': c['repo'],
                        'commit_sha': c['commit_sha'],
                        'cve': c['cve_id'],
                        'vulnerability_type': c['vulnerability_type'],
                        'owasp_category': c['owasp_category'],
                        'quality_score': c['quality_score']
                    } for c in high_quality_commits
                ]
            }
            
            with open(wartschinski_file, 'w') as f:
                json.dump(wartschinski_data, f, indent=2)
            logger.info(f"🎯 Wartschinski-ready dataset saved: {wartschinski_file}")
        
        return {
            'output_directory': str(output_path),
            'files_created': {
                'complete_dataset': str(json_file),
                'csv_summary': str(csv_file),
                'high_quality_only': str(hq_file),
                'statistics_report': str(stats_file),
                'wartschinski_ready': str(wartschinski_file) if results['summary']['ready_for_wartschinski'] else None
            }
        }

    def print_collection_summary(self, results: Dict):
        """
        Print comprehensive collection summary
        """
        print("\n" + "="*80)
        print("🎯 COMPREHENSIVE JAVA VULNERABILITY COLLECTION COMPLETE")
        print("="*80)
        
        print(f"\n📊 COLLECTION STATISTICS:")
        print(f"Total Commits Attempted: {results['statistics']['total_attempted']}")
        print(f"Successfully Collected: {results['statistics']['successfully_collected']}")
        print(f"Validation Passed: {results['statistics']['validation_passed']}")
        print(f"API Failures: {results['statistics']['api_failures']}")
        print(f"Duplicates Removed: {results['statistics']['duplicates_removed']}")
        print(f"Success Rate: {(results['statistics']['successfully_collected']/results['statistics']['total_attempted']*100):.1f}%")
        
        total = results['total_commits_collected']
        if total > 0:
            print(f"\n🏆 QUALITY ANALYSIS:")
            hq = results['quality_distribution']['high_quality']
            mq = results['quality_distribution']['medium_quality']
            lq = results['quality_distribution']['low_quality']
            
            print(f"High Quality (≥0.7): {hq} ({(hq/total)*100:.1f}%)")
            print(f"Medium Quality (0.4-0.7): {mq} ({(mq/total)*100:.1f}%)")
            print(f"Low Quality (<0.4): {lq} ({(lq/total)*100:.1f}%)")
            print(f"Average Quality Score: {results['quality_distribution']['average_quality_score']:.3f}")
            
            print(f"\n🎯 VULNERABILITY TYPE COVERAGE:")
            for vtype, count in sorted(results['vulnerability_type_distribution'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {vtype}: {count} commits")
            
            print(f"\n🏢 TOP REPOSITORIES:")
            top_repos = sorted(results['repository_coverage'].items(), key=lambda x: x[1], reverse=True)[:10]
            for repo, count in top_repos:
                print(f"  {repo}: {count} commits")
            
            print(f"\n💡 RECOMMENDATION:")
            print(f"📋 {results['summary']['recommended_action']}")
            print(f"🎓 Dataset Quality: {results['summary']['dataset_quality']}")
            
            if results['summary']['ready_for_wartschinski']:
                print(f"\n✅ READY FOR WARTSCHINSKI PIPELINE!")
                print(f"🔬 Proceed with token-level vulnerability detection training")
                print(f"📈 Expected F1-scores: 65-80% (realistic, no data leakage)")
            else:
                print(f"\n⚠️  CONSIDER ALTERNATIVE APPROACHES:")
                if total < 100:
                    print(f"📊 Combine with MoreFixes dataset (11,232 samples)")
                else:
                    print(f"🔍 Filter for high-quality commits only")
                    print(f"📊 Or supplement with proven datasets")
        
        print("\n" + "="*80)


# Main execution pipeline
def main():
    """
    Main execution function for comprehensive commit collection
    """
    print("🚀 JAVA VULNERABILITY COMMIT COLLECTION PIPELINE")
    print("Collecting, validating, and refining comprehensive dataset")
    print("="*80)
    
    # Configuration
    github_token = input("Enter your GitHub token: ").strip()
    if not github_token:
        print("❌ GitHub token required. Exiting.")
        return
    
    output_directory = input("Enter output directory (default: ./vulnerability_dataset): ").strip()
    if not output_directory:
        output_directory = "./vulnerability_dataset"
    
    # Initialize collector
    collector = ComprehensiveJavaVulnCollector(github_token)
    
    try:
        # Run comprehensive collection
        results = collector.run_comprehensive_collection()
        
        # Save all datasets
        file_info = collector.save_comprehensive_dataset(results, output_directory)
        
        # Print summary
        collector.print_collection_summary(results)
        
        print(f"\n📁 OUTPUT FILES:")
        for file_type, file_path in file_info['files_created'].items():
            if file_path:
                print(f"  {file_type}: {file_path}")
        
        print(f"\n🎯 NEXT STEPS:")
        if results['summary']['ready_for_wartschinski']:
            print("1. ✅ Dataset ready - proceed with Wartschinski pipeline")
            print("2. 🔬 Implement token-level labeling from git diffs")
            print("3. 📚 Train enhanced Word2Vec on collected samples")
            print("4. 🧠 Train LSTM with commit-based splitting")
        else:
            print("1. 📊 Review quality distribution in CSV summary")
            print("2. 🔍 Consider filtering for high-quality commits only")
            print("3. 📝 Or proceed with MoreFixes dataset (proven approach)")
        
        print("\n✅ COLLECTION PIPELINE COMPLETE!")
        
    except KeyboardInterrupt:
        print("\n⚠️  Collection interrupted by user")
        print("Partial results may be available in output directory")
    except Exception as e:
        logger.error(f"Collection failed: {e}")
        print(f"❌ Collection failed: {e}")
        print("Check logs for detailed error information")


if __name__ == "__main__":
    main()