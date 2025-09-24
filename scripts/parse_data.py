# scripts/parse_data.py

import os
import json
import sqlite3
import pandas as pd
from tqdm import tqdm

# Sanity check to make sure the correct script is running
print("Running the latest, corrected version of parse_data.py...")

# --- Configuration ---
RAW_DATA_DIR = 'datasets/raw'
PROCESSED_DATA_DIR = 'datasets/processed'

# Ensure the processed directory exists
os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)

# --- 1. Parse MegaVul Dataset ---
print("\n[1/3] Parsing MegaVul dataset...")
megavul_path = os.path.join(RAW_DATA_DIR, 'megavul', 'megavul_simple.json')
megavul_data = []
with open(megavul_path, 'r') as f:
    for line in tqdm(f, desc="Processing MegaVul"):
        try:
            record = json.loads(line)
            if record.get('lang') == 'java':
                # Add vulnerable sample
                megavul_data.append({
                    'repo_name': record.get('repo'),
                    'file_path': record.get('filepath'),
                    'vuln_code': record.get('func_before'),
                    'cwe': record.get('cve_details', {}).get('cwe_id', 'N/A'),
                    'label': 1, # 1 for vulnerable
                    'source': 'MegaVul'
                })
                # Add non-vulnerable (fixed) sample
                megavul_data.append({
                    'repo_name': record.get('repo'),
                    'file_path': record.get('filepath'),
                    'vuln_code': record.get('func_after'),
                    'cwe': 'N/A',
                    'label': 0, # 0 for non-vulnerable
                    'source': 'MegaVul'
                })
        except json.JSONDecodeError:
            continue # Skip malformed lines

df_megavul = pd.DataFrame(megavul_data)
output_path = os.path.join(PROCESSED_DATA_DIR, 'megavul_parsed.csv')
df_megavul.to_csv(output_path, index=False)
print(f"-> MegaVul parsing complete. Saved {len(df_megavul)} samples to {output_path}")

# --- 2. Parse CVEFixes Dataset ---
print("\n[2/3] Parsing CVEFixes dataset...")
cvefixes_path = os.path.join(RAW_DATA_DIR, 'cvefixes', 'CVEFixes.sqlite')
conn = sqlite3.connect(cvefixes_path)
query = "SELECT repo_name, file_path, code_before, cwe FROM java_vulnerable_code"
df_cvefixes_raw = pd.read_sql_query(query, conn)
conn.close()

df_cvefixes_raw.rename(columns={'code_before': 'vuln_code'}, inplace=True)
df_cvefixes_raw['label'] = 1
df_cvefixes_raw['source'] = 'CVEFixes'
output_path = os.path.join(PROCESSED_DATA_DIR, 'cvefixes_parsed.csv')
df_cvefixes_raw.to_csv(output_path, index=False)
print(f"-> CVEFixes parsing complete. Saved {len(df_cvefixes_raw)} samples to {output_path}")


# --- 3. Parse JavaVFC Dataset ---
print("\n[3/3] Parsing JavaVFC dataset...")
javavfc_path = os.path.join(RAW_DATA_DIR, 'javavfc', 'javavfc_extended.jsonl')

def parse_diff(diff_text):
    """A simple diff parser to extract the 'before' state of the code."""
    lines = diff_text.split('\n')
    code_before = []
    for line in lines:
        if line.startswith('-') and not line.startswith('---'):
            code_before.append(line[1:]) # Append line, removing the '-'
        elif not line.startswith('+') and not line.startswith('@@'):
            code_before.append(line)
    return "\n".join(code_before)

javavfc_data = []
with open(javavfc_path, 'r') as f:
    for line in tqdm(f, desc="Processing JavaVFC"):
        try:
            record = json.loads(line)
            if 'diff_raw' in record:
                vuln_code = parse_diff(record['diff_raw'])
                javavfc_data.append({
                    'repo_name': record.get('repo_name'),
                    'file_path': record.get('file_path'),
                    'vuln_code': vuln_code,
                    'cwe': 'N/A', # CWE not available in this dataset
                    'label': 1,
                    'source': 'JavaVFC'
                })
        except (json.JSONDecodeError, AttributeError):
            continue

df_javavfc = pd.DataFrame(javavfc_data)
output_path = os.path.join(PROCESSED_DATA_DIR, 'javavfc_parsed.csv')
df_javavfc.to_csv(output_path, index=False)
print(f"-> JavaVFC parsing complete. Saved {len(df_javavfc)} samples to {output_path}")

print("\nAll datasets parsed successfully! ✅")
