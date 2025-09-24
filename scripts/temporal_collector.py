#!/usr/bin/env python3
"""
Temporal Java Vulnerability Collector - Fixed Version
Collects vulnerability data across different time periods
"""

import json
import time
import logging
from datetime import datetime, timedelta
from java_vulnerability_scraper import JavaVulnerabilityCommitScraper

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TemporalCollector:
    def __init__(self, github_token: str):
        self.scraper = JavaVulnerabilityCommitScraper(github_token)
    
    def search_repositories_with_date_filter(self, base_query: str, start_date: str, end_date: str, max_repos: int = 100):
        """Search repositories with date filtering"""
        repositories = []
        
        # Create time-filtered queries
        date_queries = [
            f"{base_query} created:{start_date}..{end_date}",
            f"{base_query} updated:{start_date}..{end_date}",
            f"{base_query} pushed:{start_date}..{end_date}"
        ]
        
        for query in date_queries:
            if len(repositories) >= max_repos:
                break
                
            page = 1
            while len(repositories) < max_repos and page <= 5:  # Limit pages to avoid rate limits
                logger.info(f"Searching with query: '{query}' (page {page})")
                
                url = f"{self.scraper.base_url}/search/repositories"
                params = {
                    'q': query,
                    'sort': 'updated',
                    'order': 'desc', 
                    'per_page': 50,  # Smaller page size
                    'page': page
                }
                
                data = self.scraper.make_api_request(url, params)
                if not data or 'items' not in data:
                    break
                    
                repos = data['items']
                if not repos:
                    break
                    
                for repo in repos:
                    if len(repositories) >= max_repos:
                        break
                        
                    if self.scraper.is_valid_repository(repo):
                        # Check if we already have this repo
                        repo_name = repo['full_name']
                        if not any(r['name'] == repo_name for r in repositories):
                            repositories.append({
                                'name': repo['full_name'],
                                'id': repo['id'],
                                'stars': repo['stargazers_count'],
                                'language': repo['language'],
                                'created_at': repo.get('created_at'),
                                'updated_at': repo.get('updated_at')
                            })
                
                page += 1
                time.sleep(2)  # Rate limiting
        
        logger.info(f"Found {len(repositories)} repositories for period {start_date} to {end_date}")
        return repositories[:max_repos]
    
    def collect_by_time_periods(self, output_file: str = 'temporal_java_commits.json'):
        """Collect vulnerabilities from different time periods"""
        time_periods = [
            ("2024-01-01", "2024-12-31", "2024"),
            ("2023-01-01", "2023-12-31", "2023"),
            ("2022-01-01", "2022-12-31", "2022"), 
            ("2021-01-01", "2021-12-31", "2021"),
            ("2020-01-01", "2020-12-31", "2020")
        ]
        
        # Base queries for different types of security fixes
        base_queries = [
            "language:java security fix",
            "language:java vulnerability fix", 
            "language:java CVE",
            "language:java security patch",
            "language:java OWASP"
        ]
        
        all_commits = []
        
        for start_date, end_date, year_label in time_periods:
            logger.info(f"Collecting vulnerabilities from {year_label} ({start_date} to {end_date})")
            
            year_commits = []
            
            for base_query in base_queries:
                logger.info(f"  Using query: {base_query}")
                
                # Search repositories for this time period
                repos = self.search_repositories_with_date_filter(
                    base_query, start_date, end_date, max_repos=20
                )
                
                # Collect commits from each repository
                for repo in repos:
                    repo_name = repo['name']
                    logger.info(f"    Processing repository: {repo_name}")
                    
                    try:
                        commits = self.scraper.search_vulnerability_commits(repo_name, max_commits=15)
                        
                        for commit in commits:
                            # Filter commits by date
                            commit_date = commit.get('date', '')
                            if self.is_commit_in_date_range(commit_date, start_date, end_date):
                                diff_info = self.scraper.get_commit_diff(repo_name, commit['sha'])
                                if diff_info and diff_info.get('java_files'):
                                    # Add temporal metadata
                                    diff_info['collection_year'] = year_label
                                    diff_info['collection_strategy'] = 'temporal'
                                    year_commits.append(diff_info)
                                    
                    except Exception as e:
                        logger.warning(f"Error processing repository {repo_name}: {e}")
                        continue
                    
                    # Small delay between repositories
                    time.sleep(1)
                
                # Delay between different base queries
                time.sleep(3)
            
            logger.info(f"Collected {len(year_commits)} commits from {year_label}")
            all_commits.extend(year_commits)
            
            # Save intermediate results for each year
            intermediate_file = f"temporal_{year_label}_commits.json"
            with open(intermediate_file, 'w') as f:
                json.dump(year_commits, f, indent=2)
            logger.info(f"Saved intermediate results to {intermediate_file}")
        
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
        
        logger.info(f"Temporal collection saved to {output_file}")
        return unique_commits
    
    def is_commit_in_date_range(self, commit_date: str, start_date: str, end_date: str) -> bool:
        """Check if commit date falls within the specified range"""
        if not commit_date:
            return True  # Include commits without dates
        
        try:
            # Parse commit date (ISO format: 2023-05-15T10:30:00Z)
            commit_dt = datetime.fromisoformat(commit_date.replace('Z', '+00:00'))
            start_dt = datetime.fromisoformat(start_date + 'T00:00:00+00:00')
            end_dt = datetime.fromisoformat(end_date + 'T23:59:59+00:00')
            
            return start_dt <= commit_dt <= end_dt
        except (ValueError, TypeError):
            return True  # Include commits with unparseable dates
    
    def collect_recent_vulnerabilities(self, days_back: int = 365):
        """Collect vulnerabilities from recent period"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        start_str = start_date.strftime('%Y-%m-%d')
        end_str = end_date.strftime('%Y-%m-%d')
        
        logger.info(f"Collecting recent vulnerabilities from {start_str} to {end_str}")
        
        # Recent-focused queries
        recent_queries = [
            f"language:java security fix created:{start_str}..{end_str}",
            f"language:java vulnerability updated:{start_str}..{end_str}",
            f"language:java CVE-2024",
            f"language:java CVE-2023", 
            "language:java zero-day fix",
            "language:java critical security"
        ]
        
        all_commits = []
        
        for query in recent_queries:
            repos = self.search_repositories_with_date_filter(
                query.split(' created:')[0] if ' created:' in query else query,
                start_str, end_str, max_repos=25
            )
            
            for repo in repos:
                commits = self.scraper.search_vulnerability_commits(repo['name'], max_commits=20)
                for commit in commits:
                    diff_info = self.scraper.get_commit_diff(repo['name'], commit['sha'])
                    if diff_info and diff_info.get('java_files'):
                        diff_info['collection_strategy'] = 'recent'
                        all_commits.append(diff_info)
        
        # Save recent results
        with open('recent_java_commits.json', 'w') as f:
            json.dump(all_commits, f, indent=2)
        
        logger.info(f"Collected {len(all_commits)} recent commits")
        return all_commits

if __name__ == "__main__":
    # Load GitHub token
    try:
        with open('github_token.txt', 'r') as f:
            token = f.read().strip()
    except FileNotFoundError:
        print("Please create github_token.txt with your GitHub token")
        exit(1)
    
    collector = TemporalCollector(token)
    
    # Run temporal collection
    commits = collector.collect_by_time_periods('temporal_java_commits.json')
    
    # Also collect recent vulnerabilities
    recent_commits = collector.collect_recent_vulnerabilities(days_back=365)
    
    print(f"Temporal collection complete!")
    print(f"Historical commits: {len(commits)}")
    print(f"Recent commits: {len(recent_commits)}")
    print(f"Total new commits: {len(commits) + len(recent_commits)}")