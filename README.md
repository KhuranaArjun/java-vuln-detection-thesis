# Java Vulnerability Dataset Collection

This project collects and processes Java vulnerability datasets from multiple sources for machine learning research.

## Quick Start

1. **Run setup script:**
   ```bash
   ./setup.sh
   ```

2. **Test your setup:**
   ```bash
   source venv/bin/activate
   python scripts/test_setup.py
   ```

3. **Copy the processor code:**
   - Copy the Java Dataset Processor code into `scripts/java_dataset_processor.py`

4. **Configure API keys:**
   - Edit `.env` file and add your NVD API key
   - Get free API key from: https://nvd.nist.gov/developers/request-an-api-key

5. **Run the collection:**
   ```bash
   ./run_processor.sh
   ```

## Data Sources

- **MoreFixes**: 20K\\+ CVE-verified vulnerabilities (primary source)
- **NVD**: NIST National Vulnerability Database
- **Juliet Test Suite**: NIST synthetic test cases
- **Apache JIRA**: Real-world security issues

## Directory Structure

```
java-vulnerability-detection-backup/
├── datasets/
│   ├── raw/          # Raw downloaded data
│   ├── processed/    # Processed datasets
│   └── archive/      # Archived datasets
├── scripts/          # Processing scripts
├── notebooks/        # Jupyter notebooks
├── models/           # Trained models
└── results/          # Results and reports
```

## Troubleshooting

- **Docker issues**: Make sure Docker Desktop is running
- **Database connection**: Ensure PostgreSQL container is started
- **API limits**: NVD API has rate limits, be patient
- **Memory issues**: MoreFixes dataset is large (16GB uncompressed)

## Progress Tracking

The processor generates detailed reports in `datasets/processed/` showing:
- Collection statistics per source
- Data quality metrics
- Progress toward 20K sample goal
