#!/usr/bin/env python3
"""
Enhanced Java Vulnerability Data Collector
Implements multiple collection strategies to maximize dataset size
"""

import json
import time
import logging
from java_vulnerability_scraper import JavaVulnerabilityCommitScraper
from java_dataset_processor import JavaDatasetProcessor
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnhancedJavaCollector:
    def __init__(self, github_token: str):
        self.github_token = github_token
        self.scraper = JavaVulnerabilityCommitScraper(github_token)
        self.processor = JavaDatasetProcessor(context_window=10)
        
        # Expanded search strategies
        self.collection_strategies = [
            self.collect_from_cve_databases(),
            self.collect_from_security_advisories(),
            self.collect_from_popular_frameworks(),
            self.collect_from_academic_datasets(),
            self.collect_from_bug_bounty_repos()
        ]
    
    def collect_from_cve_databases(self):
        """Strategy 1: Target repositories with known CVEs"""
        cve_search_queries = [
            "language:java CVE-2023 fix",
            "language:java CVE-2022 fix", 
            "language:java CVE-2021 fix",
            "language:java security advisory",
            "language:java GHSA fix",  # GitHub Security Advisory
            "language:java vulnerability disclosure",
            "language:java security bulletin",
            "language:java patch security"
        ]
        
        all_commits = []
        for query in cve_search_queries:
            logger.info(f"Collecting from CVE databases with query: {query}")
            repos = self.scraper.search_repositories_with_query(query, max_repos=50)
            
            for repo in repos:
                commits = self.scraper.search_vulnerability_commits(repo['name'], max_commits=30)
                for commit in commits:
                    diff_info = self.scraper.get_commit_diff(repo['name'], commit['sha'])
                    if diff_info and diff_info['java_files']:
                        all_commits.append(diff_info)
                        
            time.sleep(2)  # Rate limiting
        
        return all_commits
    
    def collect_from_security_advisories(self):
        """Strategy 2: Target repositories with security advisories"""
        advisory_queries = [
            "language:java security fix Spring",
            "language:java security fix Struts", 
            "language:java security fix Hibernate",
            "language:java security fix Jackson",
            "language:java security fix Log4j",
            "language:java security fix Apache",
            "language:java OWASP fix",
            "language:java CWE fix"
        ]
        
        all_commits = []
        for query in advisory_queries:
            logger.info(f"Collecting from security advisories: {query}")
            repos = self.scraper.search_repositories_with_query(query, max_repos=30)
            
            for repo in repos:
                commits = self.scraper.search_vulnerability_commits(repo['name'], max_commits=25)
                for commit in commits:
                    diff_info = self.scraper.get_commit_diff(repo['name'], commit['sha'])
                    if diff_info and diff_info['java_files']:
                        all_commits.append(diff_info)
        
        return all_commits
    
    def collect_from_popular_frameworks(self):
        """Strategy 3: Target popular Java frameworks known for security fixes"""
        framework_repos = [
            # Web frameworks
            "spring-projects/spring-boot",
            "spring-projects/spring-framework", 
            "spring-projects/spring-security",
            "apache/struts",
            "playframework/playframework",
            
            # Application servers
            "apache/tomcat",
            "eclipse/jetty.project",
            "wildfly/wildfly",
            
            # Libraries
            "FasterXML/jackson-databind",
            "apache/commons-collections",
            "apache/commons-fileupload",
            "apache/shiro",
            
            # Build tools
            "apache/maven",
            "gradle/gradle",
            
            # Security libraries
            "jwtk/jjwt",
            "pac4j/pac4j"
        ]
        
        all_commits = []
        for repo_name in framework_repos:
            logger.info(f"Collecting from framework: {repo_name}")
            commits = self.scraper.search_vulnerability_commits(repo_name, max_commits=50)
            
            for commit in commits:
                diff_info = self.scraper.get_commit_diff(repo_name, commit['sha'])
                if diff_info and diff_info['java_files']:
                    all_commits.append(diff_info)
                    
            time.sleep(1)  # Be respectful to popular repos
        
        return all_commits
    
    def collect_from_academic_datasets(self):
        """Strategy 4: Search for academic research datasets"""
        academic_queries = [
            "language:java vulnerability dataset",
            "language:java security benchmark", 
            "language:java SARD dataset",
            "language:java Juliet test suite",
            "language:java security test cases",
            "language:java vulnerability examples"
        ]
        
        all_commits = []
        for query in academic_queries:
            logger.info(f"Collecting from academic sources: {query}")
            repos = self.scraper.search_repositories_with_query(query, max_repos=20)
            
            # Filter for legitimate research datasets, not demos
            filtered_repos = []
            for repo in repos:
                repo_name = repo['name'].lower()
                if any(term in repo_name for term in ['dataset', 'benchmark', 'research', 'study']):
                    if not any(term in repo_name for term in ['demo', 'tutorial', 'example']):
                        filtered_repos.append(repo)
            
            for repo in filtered_repos:
                commits = self.scraper.search_vulnerability_commits(repo['name'], max_commits=20)
                for commit in commits:
                    diff_info = self.scraper.get_commit_diff(repo['name'], commit['sha'])
                    if diff_info and diff_info['java_files']:
                        all_commits.append(diff_info)
        
        return all_commits
    
    def collect_from_bug_bounty_repos(self):
        """Strategy 5: Look for repositories that have had bug bounty findings"""
        bounty_queries = [
            "language:java bug bounty fix",
            "language:java HackerOne fix",
            "language:java responsible disclosure", 
            "language:java security researcher",
            "language:java penetration test fix"
        ]
        
        all_commits = []
        for query in bounty_queries:
            logger.info(f"Collecting from bug bounty sources: {query}")
            repos = self.scraper.search_repositories_with_query(query, max_repos=15)
            
            for repo in repos:
                commits = self.scraper.search_vulnerability_commits(repo['name'], max_commits=15)
                for commit in commits:
                    diff_info = self.scraper.get_commit_diff(repo['name'], commit['sha'])
                    if diff_info and diff_info['java_files']:
                        all_commits.append(diff_info)
        
        return all_commits
    
    def run_enhanced_collection(self, output_file: str = 'enhanced_java_commits.json'):
        """Run all collection strategies"""
        logger.info("Starting enhanced Java vulnerability collection...")
        
        all_commits = []
        
        # Run each strategy
        for i, strategy_func in enumerate([
            self.collect_from_cve_databases,
            self.collect_from_security_advisories, 
            self.collect_from_popular_frameworks,
            self.collect_from_academic_datasets,
            self.collect_from_bug_bounty_repos
        ], 1):
            logger.info(f"Running collection strategy {i}/5...")
            strategy_commits = strategy_func()
            all_commits.extend(strategy_commits)
            
            # Save intermediate results
            with open(f"intermediate_strategy_{i}_{output_file}", 'w') as f:
                json.dump(strategy_commits, f, indent=2)
            
            logger.info(f"Strategy {i} collected {len(strategy_commits)} commits")
        
        # Remove duplicates based on commit SHA
        unique_commits = []
        seen_shas = set()
        
        for commit in all_commits:
            sha = commit['sha']
            if sha not in seen_shas:
                unique_commits.append(commit)
                seen_shas.add(sha)
        
        logger.info(f"Total unique commits collected: {len(unique_commits)}")
        
        # Save final results
        with open(output_file, 'w') as f:
            json.dump(unique_commits, f, indent=2)
        
        return unique_commits

# Add method to existing scraper class
def search_repositories_with_query(self, query: str, max_repos: int = 100):
    """Search repositories with a specific query"""
    repositories = []
    page = 1
    
    while len(repositories) < max_repos and page <= 10:
        logger.info(f"Searching with query: '{query}' (page {page})")
        
        url = f"{self.base_url}/search/repositories"
        params = {
            'q': query,
            'sort': 'updated',
            'order': 'desc', 
            'per_page': 100,
            'page': page
        }
        
        data = self.make_api_request(url, params)
        if not data or 'items' not in data:
            break
            
        repos = data['items']
        if not repos:
            break
            
        for repo in repos:
            if self.is_valid_repository(repo):
                repositories.append({
                    'name': repo['full_name'],
                    'id': repo['id'],
                    'stars': repo['stargazers_count'],
                    'language': repo['language']
                })
        
        page += 1
        time.sleep(1)
    
    return repositories[:max_repos]

# Monkey patch the method
JavaVulnerabilityCommitScraper.search_repositories_with_query = search_repositories_with_query

if __name__ == "__main__":
    # Load GitHub token
    with open('github_token.txt', 'r') as f:
        token = f.read().strip()
    
    collector = EnhancedJavaCollector(token)
    commits = collector.run_enhanced_collection('enhanced_java_commits.json')
    
    print(f"Enhanced collection complete! Found {len(commits)} commits")