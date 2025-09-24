#!/usr/bin/env python3
"""
Complete Java Code Vulnerability Demonstrator
Shows realistic multi-line code with line-level color highlighting
"""

import re
import json
import numpy as np
from pathlib import Path
from typing import List, Dict, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class JavaCodeVulnerabilityDemo:
    def __init__(self):
        """Initialize with realistic Java vulnerability patterns"""
        
        # Color scheme for different vulnerability levels
        self.colors = {
            'safe': '#FFFFFF',         # White - no highlight
            'low': '#FFEB3B',          # Yellow
            'medium': '#FF9800',       # Orange
            'high': '#F44336',         # Red
            'critical': '#B71C1C'      # Dark Red
        }
        
        # Vulnerability scoring patterns
        self.vulnerability_patterns = [
            # Critical vulnerabilities
            {
                'pattern': r'.*SELECT.*\+.*username.*\+.*password.*',
                'severity': 'critical',
                'type': 'SQL_INJECTION',
                'score': 0.95
            },
            {
                'pattern': r'.*runtime\.exec\(.*\+.*\)',
                'severity': 'critical', 
                'type': 'COMMAND_INJECTION',
                'score': 0.90
            },
            # High vulnerabilities
            {
                'pattern': r'.*response.*print.*\+.*user.*',
                'severity': 'high',
                'type': 'XSS',
                'score': 0.80
            },
            {
                'pattern': r'.*statement.*query.*\+.*',
                'severity': 'high',
                'type': 'SQL_INJECTION', 
                'score': 0.75
            },
            # Medium vulnerabilities
            {
                'pattern': r'.*file.*path.*\+.*input.*',
                'severity': 'medium',
                'type': 'PATH_TRAVERSAL',
                'score': 0.60
            },
            {
                'pattern': r'.*password.*==.*input.*',
                'severity': 'medium',
                'type': 'WEAK_COMPARISON',
                'score': 0.55
            },
            # Low vulnerabilities
            {
                'pattern': r'.*System\.out\.print.*user.*',
                'severity': 'low',
                'type': 'INFO_DISCLOSURE',
                'score': 0.40
            }
        ]
    
    def analyze_code_lines(self, code: str) -> List[Dict]:
        """Analyze each line of code for vulnerabilities"""
        lines = code.split('\n')
        analyzed_lines = []
        
        for i, line in enumerate(lines, 1):
            line_info = {
                'line_number': i,
                'code': line,
                'severity': 'safe',
                'vulnerability_type': None,
                'score': 0.0,
                'explanation': ''
            }
            
            # Check line against vulnerability patterns
            line_lower = line.lower().strip()
            
            # Direct pattern matching for common vulnerabilities
            
            # SQL Injection - String concatenation in SQL queries
            if ('select' in line_lower or 'update' in line_lower or 'insert' in line_lower or 'delete' in line_lower):
                if ('+' in line_lower and ('username' in line_lower or 'password' in line_lower)):
                    line_info['severity'] = 'critical'
                    line_info['vulnerability_type'] = 'SQL_INJECTION'
                    line_info['score'] = 0.95
                    line_info['explanation'] = 'SQL Injection via string concatenation'
                elif '+' in line_lower:
                    line_info['severity'] = 'high'
                    line_info['vulnerability_type'] = 'SQL_INJECTION'
                    line_info['score'] = 0.80
                    line_info['explanation'] = 'Potential SQL Injection'
            
            # Command Injection
            elif 'runtime.exec' in line_lower or 'processbuilder' in line_lower:
                if '+' in line_lower:
                    line_info['severity'] = 'critical'
                    line_info['vulnerability_type'] = 'COMMAND_INJECTION'
                    line_info['score'] = 0.90
                    line_info['explanation'] = 'Command Injection via concatenation'
            
            # XSS - Response output with concatenation
            elif ('response' in line_lower or 'writer.print' in line_lower or 'println' in line_lower):
                if '+' in line_lower and ('user' in line_lower or 'message' in line_lower or 'input' in line_lower):
                    line_info['severity'] = 'high'
                    line_info['vulnerability_type'] = 'XSS'
                    line_info['score'] = 0.75
                    line_info['explanation'] = 'Cross-Site Scripting via output'
            
            # Path Traversal
            elif 'file' in line_lower and 'path' in line_lower:
                if '+' in line_lower:
                    line_info['severity'] = 'medium'
                    line_info['vulnerability_type'] = 'PATH_TRAVERSAL'
                    line_info['score'] = 0.60
                    line_info['explanation'] = 'Path Traversal vulnerability'
            
            # Information Disclosure
            elif 'system.out.print' in line_lower:
                if ('user' in line_lower or 'error' in line_lower):
                    line_info['severity'] = 'low'
                    line_info['vulnerability_type'] = 'INFO_DISCLOSURE'
                    line_info['score'] = 0.40
                    line_info['explanation'] = 'Information disclosure'
            
            # Weak comparison
            elif 'password.equals' in line_lower or 'password ==' in line_lower:
                line_info['severity'] = 'medium'
                line_info['vulnerability_type'] = 'WEAK_COMPARISON'
                line_info['score'] = 0.55
                line_info['explanation'] = 'Weak password comparison'
            
            # Logger with user input
            elif 'logger.' in line_lower and '+' in line_lower:
                if ('user' in line_lower or 'input' in line_lower):
                    line_info['severity'] = 'low'
                    line_info['vulnerability_type'] = 'LOG_INJECTION'
                    line_info['score'] = 0.35
                    line_info['explanation'] = 'Potential log injection'
            
            analyzed_lines.append(line_info)
        
        return analyzed_lines
    
    def generate_complete_html(self, code: str, title: str = "Java Vulnerability Analysis", save_path: str = None) -> str:
        """Generate complete HTML with line-level highlighting"""
        
        analyzed_lines = self.analyze_code_lines(code)
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .title {{
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 20px;
            text-align: center;
        }}
        .code-container {{
            background-color: #fafafa;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            overflow-x: auto;
        }}
        .code-line {{
            margin: 0;
            padding: 3px 8px;
            line-height: 1.4;
            border-radius: 2px;
            white-space: pre;
        }}
        .line-number {{
            color: #666;
            margin-right: 15px;
            font-weight: bold;
            min-width: 30px;
            display: inline-block;
        }}
        .safe {{ background-color: {self.colors['safe']}; }}
        .low {{ background-color: {self.colors['low']}; }}
        .medium {{ background-color: {self.colors['medium']}; }}
        .high {{ background-color: {self.colors['high']}; color: white; }}
        .critical {{ background-color: {self.colors['critical']}; color: white; }}
        .legend {{
            margin: 20px 0;
            padding: 15px;
            background-color: #f0f0f0;
            border-radius: 4px;
        }}
        .legend-item {{
            display: inline-block;
            margin: 5px 10px;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .summary {{
            margin-top: 20px;
            padding: 15px;
            background-color: #e3f2fd;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="title">{title}</div>
        
        <div class="legend">
            <strong>Vulnerability Levels:</strong>
            <span class="legend-item critical">Critical</span>
            <span class="legend-item high">High</span>
            <span class="legend-item medium">Medium</span>
            <span class="legend-item low">Low</span>
            <span class="legend-item safe">Safe</span>
        </div>
        
        <div class="code-container">
'''
        
        # Add code lines with appropriate highlighting
        for line_info in analyzed_lines:
            tooltip = f"Score: {line_info['score']:.2f}"
            if line_info['vulnerability_type']:
                tooltip += f" | Type: {line_info['vulnerability_type']}"
            
            html += f'''            <div class="code-line {line_info['severity']}" title="{tooltip}">'''
            html += f'''<span class="line-number">{line_info['line_number']:2d}:</span>{line_info['code']}</div>\n'''
        
        # Summary statistics
        vulnerability_counts = {}
        for line in analyzed_lines:
            severity = line['severity']
            vulnerability_counts[severity] = vulnerability_counts.get(severity, 0) + 1
        
        html += f'''
        </div>
        
        <div class="summary">
            <strong>Analysis Summary:</strong><br>
            Total lines: {len(analyzed_lines)}<br>
            Vulnerabilities found: {sum(v for k, v in vulnerability_counts.items() if k != 'safe')}<br>
            Distribution: {dict(vulnerability_counts)}
        </div>
    </div>
</body>
</html>
'''
        
        if save_path:
            with open(save_path, 'w') as f:
                f.write(html)
        
        return html
    
    def generate_complete_image(self, code: str, title: str = "Java Vulnerability Analysis", save_path: str = None):
        """Generate complete image with line-level highlighting"""
        try:
            import matplotlib.pyplot as plt
            import matplotlib.patches as patches
            from matplotlib.colors import hex2color
        except ImportError:
            logger.error("matplotlib required for image generation")
            return None
        
        analyzed_lines = self.analyze_code_lines(code)
        
        # Calculate figure size based on content
        num_lines = len(analyzed_lines)
        max_line_length = max(len(line['code']) for line in analyzed_lines)
        
        fig_width = min(20, max(12, max_line_length * 0.08))
        fig_height = min(16, max(8, num_lines * 0.4))
        
        fig, ax = plt.subplots(figsize=(fig_width, fig_height))
        fig.patch.set_facecolor('white')
        
        # Title
        ax.text(0.5, 0.97, title, ha='center', va='top', fontsize=16, weight='bold')
        
        # Calculate line positions
        y_start = 0.92
        line_height = 0.8 / num_lines if num_lines > 0 else 0.05
        
        # Draw code lines with backgrounds
        for i, line_info in enumerate(analyzed_lines):
            y_pos = y_start - (i * line_height)
            
            # Draw background rectangle for non-safe lines
            if line_info['severity'] != 'safe':
                color = hex2color(self.colors[line_info['severity']])
                rect = patches.Rectangle((0.05, y_pos - line_height/3), 0.9, line_height*0.8,
                                       facecolor=color, alpha=0.7, edgecolor='none')
                ax.add_patch(rect)
            
            # Line number
            ax.text(0.08, y_pos, f"{line_info['line_number']:2d}:", 
                   fontsize=10, color='gray', weight='bold',
                   fontfamily='monospace', va='center')
            
            # Code content
            text_color = 'white' if line_info['severity'] in ['high', 'critical'] else 'black'
            ax.text(0.15, y_pos, line_info['code'], 
                   fontsize=9, color=text_color,
                   fontfamily='monospace', va='center')
        
        # Legend
        legend_y = 0.08
        ax.text(0.08, legend_y, 'Vulnerability Levels:', fontsize=12, weight='bold')
        
        legend_items = [
            ('Critical', 'critical'),
            ('High', 'high'),
            ('Medium', 'medium'),
            ('Low', 'low'),
            ('Safe', 'safe')
        ]
        
        for i, (label, severity) in enumerate(legend_items):
            x_pos = 0.08 + i * 0.15
            color = hex2color(self.colors[severity])
            rect = patches.Rectangle((x_pos, legend_y - 0.04), 0.1, 0.025,
                                   facecolor=color, alpha=0.7)
            ax.add_patch(rect)
            text_color = 'white' if severity in ['high', 'critical'] else 'black'
            ax.text(x_pos + 0.05, legend_y - 0.027, label, fontsize=9,
                   ha='center', va='center', color=text_color, weight='bold')
        
        # Clean up axes
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight', facecolor='white')
            logger.info(f"Image saved to {save_path}")
        
        plt.close()
        return save_path


def create_realistic_java_examples():
    """Create realistic Java code examples with multiple lines"""
    
    examples = {
        "User Authentication System": '''public class UserAuthenticator {
    private Connection connection;
    private Logger logger;
    
    public boolean authenticateUser(String username, String password) {
        // Vulnerable SQL injection - concatenating user input directly
        String query = "SELECT * FROM users WHERE username = '" + username + 
                      "' AND password = '" + password + "'";
        
        try {
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                logger.info("User login successful: " + username);
                return true;
            }
        } catch (SQLException e) {
            System.out.println("Database error for user: " + username);
            e.printStackTrace();
        }
        return false;
    }
    
    public void resetPassword(String username, String newPassword) {
        String updateQuery = "UPDATE users SET password = '" + newPassword + 
                           "' WHERE username = '" + username + "'";
        
        try {
            Statement stmt = connection.createStatement();
            stmt.executeUpdate(updateQuery);
        } catch (SQLException e) {
            logger.error("Password reset failed for: " + username);
        }
    }
}''',

        "File Processing Service": '''public class FileProcessor {
    private Runtime runtime;
    
    public void processUserFile(String filename, String userInput) {
        // Vulnerable command injection
        String command = "cat " + filename + " | grep " + userInput;
        
        try {
            Process process = runtime.exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Found: " + line);
            }
        } catch (IOException e) {
            System.err.println("Command execution failed: " + command);
        }
    }
    
    public File getUserFile(String userPath) {
        // Vulnerable path traversal
        String filePath = "/home/user/files/" + userPath;
        return new File(filePath);
    }
    
    public void logFileAccess(String filename, String user) {
        System.out.println("File accessed: " + filename + " by user: " + user);
    }
}''',

        "Web Response Handler": '''public class WebResponseHandler {
    private HttpServletResponse response;
    private PrintWriter writer;
    
    public void displayUserMessage(String userMessage, String username) {
        try {
            writer = response.getWriter();
            
            // Vulnerable XSS - direct output of user input
            writer.println("<div class='message'>");
            writer.println("Hello " + username + "!");
            writer.println("Your message: " + userMessage);
            writer.println("</div>");
            
            response.setContentType("text/html");
        } catch (IOException e) {
            System.err.println("Response error for user: " + username);
        }
    }
    
    public void generateReport(String reportData, String userInput) {
        String htmlContent = "<html><body>" + reportData + 
                           "<p>User data: " + userInput + "</p></body></html>";
        
        try {
            writer.println(htmlContent);
        } catch (Exception e) {
            logger.error("Report generation failed");
        }
    }
}''',

        "Secure Implementation Example": '''public class SecureUserService {
    private Connection connection;
    private Logger logger;
    
    public boolean authenticateUser(String username, String password) {
        // Secure implementation using prepared statements
        String query = "SELECT id, username FROM users WHERE username = ? AND password = ?";
        
        try {
            PreparedStatement stmt = connection.prepareStatement(query);
            stmt.setString(1, username);
            stmt.setString(2, hashPassword(password));
            
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                logger.info("User login successful");
                return true;
            }
        } catch (SQLException e) {
            logger.error("Database authentication error");
        }
        return false;
    }
    
    private String hashPassword(String password) {
        // Secure password hashing implementation
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }
    
    public void processFile(String filename) {
        // Secure file processing
        Path filePath = Paths.get("/safe/directory/", filename).normalize();
        
        if (!filePath.startsWith("/safe/directory/")) {
            throw new SecurityException("Invalid file path");
        }
        
        try {
            List<String> lines = Files.readAllLines(filePath);
            logger.info("File processed successfully");
        } catch (IOException e) {
            logger.error("File processing error");
        }
    }
}'''
    }
    
    return examples


def test_complete_java_demo():
    """Test the complete Java vulnerability demonstrator"""
    
    demo = JavaCodeVulnerabilityDemo()
    examples = create_realistic_java_examples()
    
    output_dir = Path("complete_java_vulnerability_demo")
    output_dir.mkdir(exist_ok=True)
    
    print("Generating complete Java vulnerability demonstrations...")
    
    for i, (name, code) in enumerate(examples.items(), 1):
        print(f"\n--- {name} ---")
        
        # Generate HTML
        html_file = output_dir / f"demo_{i}_{name.lower().replace(' ', '_')}.html"
        demo.generate_complete_html(code, f"Java Vulnerability Analysis - {name}", str(html_file))
        
        # Generate Image
        image_file = output_dir / f"demo_{i}_{name.lower().replace(' ', '_')}.png"
        demo.generate_complete_image(code, f"Java Vulnerability Analysis - {name}", str(image_file))
        
        # Show analysis
        analyzed_lines = demo.analyze_code_lines(code)
        vulnerable_lines = [line for line in analyzed_lines if line['severity'] != 'safe']
        
        print(f"Total lines: {len(analyzed_lines)}")
        print(f"Vulnerable lines: {len(vulnerable_lines)}")
        print(f"Vulnerabilities found: {[line['vulnerability_type'] for line in vulnerable_lines if line['vulnerability_type']]}")
        print(f"HTML: {html_file}")
        print(f"Image: {image_file}")
    
    print(f"\nAll demonstrations saved to: {output_dir}")
    print("✓ Complete Java vulnerability demonstration finished!")


if __name__ == "__main__":
    test_complete_java_demo()