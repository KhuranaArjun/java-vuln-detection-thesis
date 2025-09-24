# Java Vulnerability Detection: Machine Learning Research

**Adapting Wartschinski's VUDENC Methodology for Java Source Code**

This repository contains the complete implementation of a Java vulnerability detection system using machine learning approaches, specifically adapting Laura Wartschinski's token-level vulnerability detection methodology from Python to Java enterprise applications.

## Research Overview

**Objective**: Develop a comprehensive vulnerability detection system for Java source code using ensemble machine learning architectures with token-level granularity for precise vulnerability localization.

**Current Performance**: 71.8% accuracy using stacked ensemble approach (BiLSTM + CNN + Transformer + Random Forest meta-learner)

**Key Innovation**: Successfully adapted VUDENC's token-level vulnerability detection from Python to Java while maintaining visualization capabilities for practical security analysis.

## Quick Start

1. **Environment Setup:**
   ```bash
   # Create virtual environment
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   ```

2. **Dataset Preparation:**
   ```bash
   # Extract from MoreFixes database (primary source)
   python scripts/data_processing/morefixes_extractor.py
   
   # Process and enhance classification
   python scripts/data_processing/vulnerability_classifier.py
   ```

3. **Model Training:**
   ```bash
   # Train individual models
   python scripts/models/train_bilstm.py
   python scripts/models/train_cnn.py  
   python scripts/models/train_transformer.py
   
   # Create ensemble
   python scripts/ensemble/stacked_ensemble_trainer.py
   ```

4. **Vulnerability Demonstration:**
   ```bash
   # Run Wartschinski-style visualization
   python java_vulnerability_visualizer.py
   ```

## Dataset Composition

**Primary Dataset**: 15,044 high-quality Java vulnerability samples
- **Source Distribution**:
  - MoreFixes Database: 11,232 CVE-verified samples (September 2024)
  - Kaggle Vulnerability Dataset: 2,500+ samples
  - Intentionally Vulnerable Applications: 1,000+ samples
  - Manual curation and validation: 1,300+ samples

**Vulnerability Type Distribution**:
- SQL Injection: 810 samples (5.4%)
- Path Traversal: 1,429 samples (9.5%)
- Command Injection: 684 samples (4.5%)
- Cross-Site Scripting: 92 samples (1.8%)
- Input Validation: 3,004 samples (20.0%)
- Configuration Error: 1,461 samples (9.7%)
- Access Control: 1,064 samples (7.1%)
- Other Security: 1,672 samples (11.1%)
- Unknown Security: 2,931 samples (19.5%)

**Quality Metrics**:
- Temporal coverage: 2020-2024
- Repository diversity: 1,000+ unique Java projects
- Framework coverage: Spring, Hibernate, Jakarta EE, Android

## Model Architecture

### Individual Models
- **BiLSTM**: 68.8% accuracy - Sequential vulnerability pattern analysis
- **CNN**: 69.0% accuracy - Local pattern recognition (97% precision on Command Injection)  
- **Transformer**: 66.3% accuracy - Long-range dependency modeling

### Ensemble Approach  
- **Stacked Ensemble**: 71.8% accuracy using Random Forest meta-learner
- **Confidence-based routing**: Dynamic model selection per vulnerability type
- **Class-specific optimization**: Tailored thresholds for each vulnerability class

## Key Features

### Token-Level Vulnerability Detection
```python
# Example: Precise vulnerability localization
vulnerable_tokens = analyzer.predict_token_vulnerability(java_code)
# Returns: List of (token, vulnerability_type, confidence_score)
```

### Wartschinski-Style Visualization
- Line-by-line code analysis with color-coded severity
- Interactive HTML output with tooltips
- Publication-ready PNG images
- Realistic Java enterprise application examples

### Framework-Aware Analysis
- Spring Security context detection  
- Hibernate ORM vulnerability patterns
- Jakarta EE security constraint analysis
- Android-specific vulnerability detection

## Directory Structure

```
java-vulnerability-detection/
├── README.md
├── requirements.txt
├── src/
│   ├── models/
│   │   ├── bilstm_model.py
│   │   ├── cnn_model.py
│   │   ├── transformer_model.py
│   │   └── ensemble_meta_learner.py
│   ├── data_processing/
│   │   ├── morefixes_extractor.py
│   │   ├── vulnerability_classifier.py
│   │   └── java_tokenizer.py
│   ├── visualization/
│   │   └── java_vulnerability_visualizer.py
│   └── ensemble/
│       └── stacked_ensemble_trainer.py
├── datasets/
│   ├── final_dataset_15044_samples.json
│   ├── train_split_70_percent.json
│   ├── validation_split_15_percent.json
│   └── test_split_15_percent.json
├── trained_models/
│   ├── bilstm_best_model.h5
│   ├── cnn_vulnerability_model.h5
│   ├── transformer_java_vuln.h5
│   └── stacked_ensemble_meta_learner.pkl
├── demonstration_outputs/
│   ├── user_authentication_system.html
│   ├── user_authentication_system.png
│   ├── file_processing_service.html
│   ├── web_response_handler.html
│   └── secure_implementation_example.html
├── results/
│   ├── performance_comparison.json
│   ├── vulnerability_type_accuracy.json
│   └── confusion_matrices/
├── config/
│   ├── model_hyperparameters.json
│   ├── vulnerability_patterns.json
│   └── ensemble_weights.json
└── docs/
    ├── METHODOLOGY.md
    ├── DATASET_DOCUMENTATION.md
    └── MODEL_ARCHITECTURE.md
```

## Research Contributions

### Methodological Innovations
1. **Cross-Language Adaptation**: Successfully adapted VUDENC from Python to Java
2. **Enterprise Framework Integration**: Framework-aware vulnerability detection  
3. **Multi-Architecture Ensemble**: Novel combination of CNN, BiLSTM, and Transformer models
4. **Token-Level Visualization**: Practical demonstration system for vulnerability education

### Performance Achievements
- **71.8% Ensemble Accuracy**: Significant improvement over 50-80% false positive rates of traditional static analysis
- **Vulnerability-Specific Excellence**: 97% precision on Command Injection, 96% on Path Traversal, 93% on SQL Injection
- **Real-World Applicability**: Tested on enterprise Java applications with practical deployment considerations

### Dataset Contributions  
- **Comprehensive Java Vulnerability Collection**: 15,044 samples with CVE verification
- **Quality Enhancement Pipeline**: Reduced unknown classifications from 97% to 22%
- **Temporal and Framework Diversity**: Broad coverage across Java ecosystem evolution

## Demonstration Examples

The system generates realistic vulnerability demonstrations:

**SQL Injection Detection**:
```java
// Lines highlighted in RED (Critical)
String query = "SELECT * FROM users WHERE username = '" + username + 
              "' AND password = '" + password + "'";
```

**Secure Code Recognition**:
```java  
// Lines remain WHITE (Safe)
PreparedStatement stmt = connection.prepareStatement(
    "SELECT * FROM users WHERE username = ? AND password = ?");
stmt.setString(1, username);
```

## Performance Benchmarks

### Individual Model Results
| Model | Accuracy | Strengths |
|-------|----------|-----------|
| BiLSTM | 68.8% | Sequential patterns, SQL injection chains |
| CNN | 69.0% | Local patterns, Command injection (97% precision) |
| Transformer | 66.3% | Long-range dependencies, complex methods |

### Ensemble Results
| Approach | Accuracy | Key Advantage |
|----------|----------|---------------|
| Simple Voting | 69.5% | Baseline ensemble |
| Weighted Average | 70.3% | Confidence-based weighting |
| Stacked (Random Forest) | **71.8%** | Intelligent meta-learning |

## Known Limitations

- **Inference Time**: 2.3 seconds per Java class (optimization ongoing)
- **Memory Requirements**: 8GB for full ensemble inference
- **Rare Vulnerability Types**: Limited samples for serialization attacks, reflection exploits
- **Framework Evolution**: Requires periodic retraining for new framework versions

## Future Research Directions

1. **Graph Neural Networks**: Method call chain and data flow analysis
2. **Expert Validation**: Industry partnership for ground truth verification
3. **Real-Time Optimization**: Sub-second inference for IDE integration
4. **Cross-Language Transfer**: Python-Java knowledge sharing
5. **Continuous Learning**: Feedback integration from security practitioners

## Related Research

This work builds upon and extends:
- **Wartschinski, L. (2022)**: VUDENC methodology for Python
- **Chakraborty, S. (2021)**: Deep learning vulnerability detection survey  
- **Russell, R. (2018)**: Deep representation learning for vulnerabilities
- **Zhou, Y. (2019)**: Graph neural networks for program semantics
- **Fan, J. (2020)**: CVE-based vulnerability dataset construction

## Installation Requirements

**System Requirements**:
- Python 3.8+
- 16GB RAM (recommended for full dataset processing)
- GPU support (optional, for faster training)
- PostgreSQL (for MoreFixes database access)

**Key Dependencies**:
- TensorFlow 2.13+
- PyTorch 2.0+
- scikit-learn 1.3+
- transformers 4.30+
- javalang 0.13+ (Java code parsing)

## Citation

If you use this work in your research, please cite:
```bibtex
@mastersthesis{khurana2025java,
  title={Machine Learning Approaches for Java Vulnerability Detection: 
         Adapting Wartschinski's VUDENC Methodology},
  author={Khurana, Arjun},
  school={University of Passau},
  year={2025},
  type={Master's Thesis}
}
```

## Contact

**Author**: Arjun Khurana  
**Supervisor**: Prof. Dr. Joachim Posegga  
**Co-Supervisor**: Ms. Talaya Farasat  
**University**: University of Passau  
**Year**: 2025

For questions about the research methodology or implementation details, please refer to the documentation in the `docs/` directory or contact the research team.

## License

This research is conducted for academic purposes. Dataset usage follows respective source licensing (MoreFixes, NVD, etc.). Please ensure compliance with individual dataset licenses for any derivative work.

---

**Current Status**: Research in progress, thesis completion scheduled November 2025  
**Latest Update**: September 2025 - Ensemble optimization and visualization system completion