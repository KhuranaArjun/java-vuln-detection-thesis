# Ins#!/usr/bin/env python3
"""
Apache JIRA Vulnerability Collector
Targets underrepresented vulnerability classes with focus on:
- Insecure Deserialization (Jackson, Commons Collections)
- Broken Access Control (Spring Security, OAuth)
- XSS (Template engines, frameworks)
"""

import requests
import json
import time
import re
from pathlib import Path
from datetime import datetime
import logging
from typing import List, Dict, Optional
import csv

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ApacheJIRACollector:
    def __init__(self, output_dir: str = "~/js-vuln-dataset/data/apache_jira"):
        self.output_dir = Path(output_dir).expanduser()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Target projects with JavaScript/Node.js vulnerabilities
        self.target_projects = {
            # High priority for deserialization
            'JACKSON': {
                'url': 'https://issues.apache.org/jira/rest/api/2/search',
                'project': 'JACKSON',
                'focus': 'INSECURE_DESERIALIZATION',
                'keywords': ['CVE', 'security', 'deserialization', 'vulnerability', 'RCE']
            },
            # Web frameworks - access control & XSS
            'STRUTS': {
                'url': 'https://issues.apache.org/jira/rest/api/2/search', 
                'project': 'WW',  # Struts project key
                'focus': 'XSS,BROKEN_ACCESS_CONTROL',
                'keywords': ['CVE', 'XSS', 'security', 'authentication', 'authorization']
            },
            # Spring projects
            'SPR': {
                'url': 'https://github.com/spring-projects/spring-framework/issues',
                'project': 'SPR',
                'focus': 'BROKEN_ACCESS_CONTROL,XSS',
                'keywords': ['CVE', 'security', 'access control', 'authentication']
            },
            # Node.js ecosystem
            'NODEJS': {
                'url': 'https://github.com/nodejs/node/issues',
                'project': 'NODE',
                'focus': 'INSECURE_DESERIALIZATION,COMMAND_INJECTION',
                'keywords': ['CVE', 'security', 'vulnerability', 'deserialization']
            }
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        self.collected_data = []
        
    def search_apache_jira(self, project: str, keywords: List[str], max_results: int = 1000) -> List[Dict]:
        """Search Apache JIRA for security-related issues"""
        
        # Build JQL query focusing on security issues
        jql_keywords = ' OR '.join([f'summary ~ "{kw}" OR description ~ "{kw}"' for kw in keywords])
        jql_query = f"""
        project = {project} AND 
        ({jql_keywords}) AND
        (labels = "security" OR labels = "vulnerability" OR summary ~ "CVE-")
        ORDER BY created DESC
        """
        
        params = {
            'jql': jql_query,
            'maxResults': max_results,
            'startAt': 0,
            'fields': 'summary,description,created,updated,priority,labels,fixVersions,status,components'
        }
        
        try:
            logger.info(f"Searching {project} with query: {jql_query[:100]}...")
            response = self.session.get(
                'https://issues.apache.org/jira/rest/api/2/search',
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                issues = data.get('issues', [])
                logger.info(f"Found {len(issues)} issues in {project}")
                return issues
            else:
                logger.warning(f"JIRA API returned status {response.status_code} for {project}")
                return []
                
        except Exception as e:
            logger.error(f"Error searching {project}: {e}")
            return []
    
    def extract_cve_info(self, text: str) -> List[str]:
        """Extract CVE identifiers from text"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return re.findall(cve_pattern, text, re.IGNORECASE)
    
    def classify_vulnerability_type(self, issue: Dict, project_focus: str) -> str:
        """Classify vulnerability type based on content"""
        text = f"{issue.get('summary', '')} {issue.get('description', '')}".lower()
        
        # Deserialization patterns
        if any(term in text for term in ['deserialization', 'jackson', 'objectmapper', 'gadget', 'rce']):
            return 'INSECURE_DESERIALIZATION'
        
        # Access control patterns  
        if any(term in text for term in ['access control', 'authentication', 'authorization', 'bypass', 'privilege']):
            return 'BROKEN_ACCESS_CONTROL'
            
        # XSS patterns
        if any(term in text for term in ['xss', 'cross-site scripting', 'script injection', 'html injection']):
            return 'XSS'
            
        # XXE patterns
        if any(term in text for term in ['xxe', 'xml external entity', 'xml injection']):
            return 'XXE'
            
        # SQL Injection patterns
        if any(term in text for term in ['sql injection', 'sqli', 'database injection']):
            return 'SQL_INJECTION'
            
        # CSRF patterns
        if any(term in text for term in ['csrf', 'cross-site request forgery']):
            return 'CSRF'
            
        # Default to project focus
        return project_focus.split(',')[0]
    
    def process_issue(self, issue: Dict, project: str, project_focus: str) -> Optional[Dict]:
        """Process a single JIRA issue into our format"""
        
        fields = issue.get('fields', {})
        summary = fields.get('summary', '')
        description = fields.get('description', '')
        
        # Extract CVEs
        cves = self.extract_cve_info(f"{summary} {description}")
        
        # Skip if no clear security relevance
        security_keywords = ['security', 'vulnerability', 'cve', 'exploit', 'malicious']
        if not any(keyword in f"{summary} {description}".lower() for keyword in security_keywords):
            return None
        
        # Classify vulnerability type
        vuln_type = self.classify_vulnerability_type(fields, project_focus)
        
        processed_issue = {
            'source': 'apache_jira',
            'project': project,
            'issue_key': issue.get('key'),
            'summary': summary,
            'description': description,
            'vulnerability_type': vuln_type,
            'cve_ids': ','.join(cves) if cves else '',
            'created': fields.get('created'),
            'updated': fields.get('updated'),
            'priority': fields.get('priority', {}).get('name', '') if fields.get('priority') else '',
            'status': fields.get('status', {}).get('name', '') if fields.get('status') else '',
            'labels': ','.join(fields.get('labels', [])),
            'components': ','.join([c.get('name', '') for c in fields.get('components', [])]),
            'url': f"https://issues.apache.org/jira/browse/{issue.get('key')}",
            'collection_date': datetime.now().isoformat()
        }
        
        return processed_issue
    
    def collect_github_security_advisories(self, repo: str, keywords: List[str]) -> List[Dict]:
        """Collect from GitHub security advisories for specific repos"""
        
        # GitHub GraphQL API for security advisories
        query = """
        query($repo_owner: String!, $repo_name: String!, $after: String) {
          repository(owner: $repo_owner, name: $repo_name) {
            vulnerabilityAlerts(first: 100, after: $after) {
              pageInfo {
                hasNextPage
                endCursor
              }
              nodes {
                createdAt
                dismissedAt
                securityAdvisory {
                  ghsaId
                  publishedAt
                  summary
                  description
                  severity
                  cvss {
                    score
                  }
                  cwes(first: 10) {
                    nodes {
                      cweId
                      name
                    }
                  }
                  identifiers {
                    type
                    value
                  }
                }
                securityVulnerability {
                  package {
                    name
                    ecosystem
                  }
                  severity
                  vulnerableVersionRange
                }
              }
            }
          }
        }
        """
        
        # This would require GitHub token - simplified version using REST API
        owner, name = repo.split('/')
        url = f"https://api.github.com/repos/{owner}/{name}/security-advisories"
        
        try:
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"GitHub API returned {response.status_code} for {repo}")
                return []
        except Exception as e:
            logger.error(f"Error fetching GitHub advisories for {repo}: {e}")
            return []
    
    def collect_all_sources(self):
        """Collect from all configured sources"""
        
        logger.info("Starting Apache JIRA vulnerability collection")
        
        for project_name, config in self.target_projects.items():
            logger.info(f"Collecting from {project_name}...")
            
            if 'github.com' in config['url']:
                # Handle GitHub repos differently
                continue
            else:
                # Handle JIRA projects
                issues = self.search_apache_jira(
                    config['project'], 
                    config['keywords'],
                    max_results=500
                )
                
                for issue in issues:
                    processed = self.process_issue(issue, project_name, config['focus'])
                    if processed:
                        self.collected_data.append(processed)
            
            # Rate limiting
            time.sleep(2)
        
        logger.info(f"Collected {len(self.collected_data)} vulnerability records")
        
    def save_results(self):
        """Save collected data to CSV"""
        
        if not self.collected_data:
            logger.warning("No data collected")
            return
        
        # Group by vulnerability type for analysis
        by_type = {}
        for item in self.collected_data:
            vuln_type = item['vulnerability_type']
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(item)
        
        # Save main dataset
        output_file = self.output_dir / f"apache_jira_vulnerabilities_{datetime.now().strftime('%Y%m%d')}.csv"
        
        if self.collected_data:
            fieldnames = self.collected_data[0].keys()
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.collected_data)
        
        logger.info(f"Saved {len(self.collected_data)} records to {output_file}")
        
        # Save summary statistics
        summary_file = self.output_dir / f"collection_summary_{datetime.now().strftime('%Y%m%d')}.txt"
        with open(summary_file, 'w') as f:
            f.write("Apache JIRA Collection Summary\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Total Records: {len(self.collected_data)}\n")
            f.write(f"Collection Date: {datetime.now().isoformat()}\n\n")
            
            f.write("Vulnerability Type Distribution:\n")
            for vuln_type, items in by_type.items():
                f.write(f"  {vuln_type}: {len(items)} records\n")
            
            f.write("\nCVE Coverage:\n")
            cve_count = sum(1 for item in self.collected_data if item['cve_ids'])
            f.write(f"  Records with CVEs: {cve_count}\n")
            f.write(f"  Records without CVEs: {len(self.collected_data) - cve_count}\n")
        
        logger.info(f"Saved summary to {summary_file}")
        
        # Print summary
        print("\n" + "="*50)
        print("APACHE JIRA COLLECTION RESULTS")
        print("="*50)
        for vuln_type, items in by_type.items():
            print(f"{vuln_type}: {len(items)} records")
        print(f"\nTotal: {len(self.collected_data)} records")
        print(f"CVE-verified: {cve_count} records")

def main():
    collector = ApacheJIRACollector()
    collector.collect_all_sources()
    collector.save_results()

if __name__ == "__main__":
    main()
# (The content from the apache_jira_collector artifact)
