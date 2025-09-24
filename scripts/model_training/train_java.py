#!/usr/bin/env python3
"""
Setup script for Java vulnerability detection training environment
"""

import subprocess
import sys
import pkg_resources
from pathlib import Path

def install_requirements():
    """Install required packages for training"""
    requirements = [
        "torch>=1.9.0",
        "transformers>=4.20.0",
        "scikit-learn>=1.0.0",
        "pandas>=1.3.0",
        "numpy>=1.21.0",
        "datasets>=2.0.0",
        "accelerate>=0.12.0",
        "tokenizers>=0.12.0"
    ]
    
    print("Installing training requirements...")
    
    for req in requirements:
        try:
            pkg_resources.require(req.split(">=")[0])
            print(f"Already installed: {req}")
        except pkg_resources.DistributionNotFound:
            print(f"Installing: {req}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", req])
    
    print("Requirements installation completed")

def create_training_config():
    """Create training configuration file"""
    config = {
        "project_name": "java_vulnerability_detection",
        "approach": "three_pillars_composite_dataset",
        "version": "2.0",
        "training": {
            "batch_size": 8,
            "learning_rate": 2e-5,
            "num_epochs": 3,
            "warmup_steps": 500,
            "weight_decay": 0.01,
            "max_seq_length": 512
        },
        "models": {
            "baseline_rf": {
                "type": "sklearn",
                "n_estimators": 100,
                "max_depth": 10
            },
            "baseline_lr": {
                "type": "sklearn",
                "max_iter": 1000
            },
            "codebert": {
                "type": "transformer",
                "model_name": "microsoft/codebert-base"
            },
            "roberta": {
                "type": "transformer",
                "model_name": "roberta-base"
            }
        },
        "target_cwes": [
            "CWE-89",
            "CWE-79", 
            "CWE-78",
            "CWE-22",
            "CWE-862",
            "CWE-306"
        ],
        "evaluation": {
            "test_size": 0.2,
            "val_size": 0.2,
            "splitting_strategy": "repository_level",
            "metrics": ["accuracy", "precision", "recall", "f1", "auc"]
        }
    }
    
    import json
    with open("config.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print("Created config.json")

def setup_directories():
    """Create necessary directory structure"""
    directories = [
        "models/checkpoints",
        "models/trained_models", 
        "models/model_configs",
        "results/three_pillars_approach",
        "results/evaluation_benchmarks",
        "notebooks/training_analysis"
    ]
    
    for dir_path in directories:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    print("Created directory structure")

def main():
    print("Setting up Java vulnerability detection training environment")
    
    install_requirements()
    create_training_config() 
    setup_directories()
    
    print("\nSetup completed successfully!")
    print("\nNext steps:")
    print("1. Ensure your data is in datasets/processed/")
    print("2. Run: python scripts/model_training/train_java_vuln.py")
    print("3. Monitor training progress in results/")

if __name__ == "__main__":
    main()
