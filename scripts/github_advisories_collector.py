#!/usr/bin/env python3
"""
GitHub Security Advisories Collector - FIXED VERSION
- Saves data incrementally (every 100 pages)
- Adds proper pagination end detection
- Limits total pages to prevent infinite loops
- Immediate crash recovery
"""

import requests
import json
import time
from pathlib import Path
from datetime import datetime
import logging
import csv
import signal
import sys
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GitHubAdvisoriesCollectorFixed:
    def __init__(self, output_dir: str = None):
        # Auto-detect output directory
        possible_dirs = [
            Path("~/java-vulnerability-detection-backup/datasets/raw/github_advisories").expanduser(),
            Path("~/java-vulnerability-detection-backup/data/github_advisories").expanduser(),
            Path("./data/github_advisories"),
            Path("./github_advisories")
        ]
        
        if output_dir:
            self.output_dir = Path(output_dir).expanduser()
        else:
            # Find existing directory or create first one
            self.output_dir = None
            for dir_path in possible_dirs:
                if dir_path.parent.exists():
                    self.output_dir = dir_path
                    break
            
            if not self.output_dir:
                self.output_dir = possible_dirs[0]  # Default to first option
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Output directory: {self.output_dir}")
        
        # GitHub API setup
        self.api_base = "https://api.github.com"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Research; Vulnerability Detection)',
            'Accept': 'application/vnd.github.v3+json',
            'X-GitHub-Api-Version': '2022-11-28'
        })
        
        # Add GitHub token if available
        github_token = os.getenv('GITHUB_TOKEN')  # Set your token here if available
        if github_token:
            self.session.headers['Authorization'] = f'token {github_token}'
            logger.info("Using GitHub token for better rate limits")
        
        # Configuration
        self.max_pages = 4000  # LIMIT: Only fetch 100 pages (10,000 advisories max)
        self.save_interval = 500  # Save every 50 pages
        self.collected_data = []
        
        # Setup graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Output file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_file = self.output_dir / f"github_advisories_{timestamp}.csv"
        self.temp_file = self.output_dir / f"github_advisories_temp_{timestamp}.csv"
        
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        logger.info("Interrupt received, saving data...")
        self.save_current_data()
        sys.exit(0)
    
    def is_relevant_advisory(self, advisory):
        """Quick relevance check for Java vulnerabilities"""
        text = f"{advisory.get('summary', '')} {advisory.get('description', '')}".lower()
        
        # Java-related keywords
        java_keywords = ['java', 'jackson', 'spring', 'servlet', 'struts', 'hibernate']
        if not any(keyword in text for keyword in java_keywords):
            return False
        
        # Target vulnerability types
        vuln_keywords = [
            'deserialization', 'access control', 'authentication', 'authorization',
            'xss', 'cross-site scripting', 'xxe', 'xml external entity'
        ]
        
        return any(keyword in text for keyword in vuln_keywords)
    
    def classify_vulnerability_type(self, advisory):
        """Classify vulnerability type"""
        text = f"{advisory.get('summary', '')} {advisory.get('description', '')}".lower()
        
        if any(term in text for term in ['deserialization', 'deserialize', 'jackson']):
            return 'INSECURE_DESERIALIZATION'
        elif any(term in text for term in ['xss', 'cross-site scripting']):
            return 'XSS'
        elif any(term in text for term in ['xxe', 'xml external entity']):
            return 'XXE'
        elif any(term in text for term in ['access control', 'authentication', 'authorization']):
            return 'BROKEN_ACCESS_CONTROL'
        else:
            return 'OTHER'
    
    def process_advisory(self, advisory):
        """Process single advisory"""
        if not self.is_relevant_advisory(advisory):
            return None
        
        vuln_type = self.classify_vulnerability_type(advisory)
        
        # Extract vulnerabilities info
        vulnerabilities = advisory.get('vulnerabilities', [])
        affected_packages = []
        for vuln in vulnerabilities:
            package = vuln.get('package', {})
            if package.get('ecosystem') in ['maven', 'gradle', 'npm']:  # Java/JS ecosystems
                affected_packages.append(package.get('name', ''))
        
        processed = {
            'ghsa_id': advisory.get('ghsa_id', ''),
            'cve_id': advisory.get('cve_id', ''),
            'summary': advisory.get('summary', ''),
            'description': advisory.get('description', ''),
            'vulnerability_type': vuln_type,
            'severity': advisory.get('severity', ''),
            'published_at': advisory.get('published_at', ''),
            'affected_packages': ','.join(affected_packages),
            'url': f"https://github.com/advisories/{advisory.get('ghsa_id', '')}",
            'collection_date': datetime.now().isoformat()
        }
        
        return processed
    
    def save_current_data(self):
        """Save currently collected data"""
        if not self.collected_data:
            logger.warning("No data to save")
            return
        
        # Save to temporary file first
        with open(self.temp_file, 'w', newline='', encoding='utf-8') as csvfile:
            if self.collected_data:
                fieldnames = self.collected_data[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.collected_data)
        
        # Move temp file to final file
        self.temp_file.rename(self.output_file)
        
        logger.info(f"Saved {len(self.collected_data)} advisories to {self.output_file}")
        
        # Print summary
        by_type = {}
        for item in self.collected_data:
            vtype = item['vulnerability_type']
            by_type[vtype] = by_type.get(vtype, 0) + 1
        
        print(f"\n📊 COLLECTION SUMMARY")
        print("=" * 40)
        for vtype, count in by_type.items():
            print(f"{vtype}: {count} advisories")
        print(f"Total: {len(self.collected_data)} advisories")
        print(f"Saved to: {self.output_file}")
    
    def collect_advisories(self):
        """Collect advisories with proper pagination limits"""
        logger.info(f"Starting GitHub advisories collection (max {self.max_pages} pages)")
        
        page = 1
        consecutive_empty = 0
        
        while page <= self.max_pages:
            url = f"{self.api_base}/advisories"
            params = {
                'per_page': 100,
                'page': page
            }
            
            try:
                logger.info(f"Fetching page {page}/{self.max_pages}...")
                response = self.session.get(url, params=params, timeout=30)
                
                if response.status_code == 200:
                    advisories = response.json()
                    
                    if not advisories:
                        consecutive_empty += 1
                        logger.info(f"Empty page {page}, consecutive empty: {consecutive_empty}")
                        
                        if consecutive_empty >= 3:
                            logger.info("3 consecutive empty pages, stopping collection")
                            break
                    else:
                        consecutive_empty = 0
                        
                        # Process advisories
                        page_relevant = 0
                        for advisory in advisories:
                            processed = self.process_advisory(advisory)
                            if processed:
                                self.collected_data.append(processed)
                                page_relevant += 1
                        
                        logger.info(f"Page {page}: {len(advisories)} total, {page_relevant} relevant")
                    
                    # Save periodically
                    if page % self.save_interval == 0:
                        logger.info(f"Intermediate save at page {page}")
                        self.save_current_data()
                    
                    page += 1
                    
                    # Rate limiting
                    time.sleep(1)
                    
                elif response.status_code == 403:
                    logger.warning("Rate limited, waiting 60 seconds...")
                    time.sleep(60)
                    continue
                else:
                    logger.error(f"API error: {response.status_code}")
                    break
                    
            except Exception as e:
                logger.error(f"Error fetching page {page}: {e}")
                break
        
        # Final save
        logger.info("Collection complete, saving final data...")
        self.save_current_data()

def main():
    collector = GitHubAdvisoriesCollectorFixed()
    collector.collect_advisories()

if __name__ == "__main__":
    main()