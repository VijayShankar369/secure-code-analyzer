# GitLab CI SAST Pipeline Integration

## .gitlab-ci.yml Configuration

```yaml
stages:
  - build
  - test
  - security
  - deploy

variables:
  DOCKER_IMAGE: "secure-code-analyzer:$CI_COMMIT_SHA"
  REPORTS_DIR: "security-reports"

# Build the scanner image
build_scanner:
  stage: build
  services:
    - docker:dind
  script:
    - docker build -t $DOCKER_IMAGE .
    - docker tag $DOCKER_IMAGE secure-code-analyzer:latest
  only:
    changes:
      - Dockerfile
      - pyproject.toml
      - src/**/*
      - rules/**/*

# SAST Security Scan
sast_scan:
  stage: security
  services:
    - docker:dind
  before_script:
    - mkdir -p $REPORTS_DIR
  script:
    # Run scan with controlled failure
    - |
      docker run --rm \
        -v $PWD:/code \
        -v $PWD/$REPORTS_DIR:/reports \
        secure-code-analyzer:latest \
        scan /code --json /reports/gl-sast-report.json --fail-on critical || SCAN_FAILED=true
    
    # Convert to GitLab SAST format (optional)
    - |
      if [ -f "$REPORTS_DIR/gl-sast-report.json" ]; then
        python3 scripts/convert_to_gitlab_sast.py \
          --input $REPORTS_DIR/gl-sast-report.json \
          --output $REPORTS_DIR/gl-sast-report.json
      fi
    
    # Handle scan results
    - |
      if [ "$SCAN_FAILED" = "true" ]; then
        echo "⚠️ Security vulnerabilities found - check artifacts"
        exit 1
      else
        echo "✅ Security scan passed"
      fi
  
  artifacts:
    reports:
      sast: $REPORTS_DIR/gl-sast-report.json
    paths:
      - $REPORTS_DIR/
    expire_in: 1 week
    when: always
  
  allow_failure: true  # Don't block pipeline on security issues
  
# Alternative: Monitor-only scan
sast_monitor:
  stage: security
  services:
    - docker:dind
  script:
    - mkdir -p $REPORTS_DIR
    - |
      docker run --rm \
        -v $PWD:/code \
        -v $PWD/$REPORTS_DIR:/reports \
        secure-code-analyzer:latest \
        scan /code --json /reports/monitor-report.json --fail-on none
    - echo "Monitor-only scan completed"
  
  artifacts:
    paths:
      - $REPORTS_DIR/
    expire_in: 1 week
  
  when: manual  # Run manually for monitoring

# Deploy only if security scan passes
deploy_production:
  stage: deploy
  script:
    - echo "Deploying to production..."
  dependencies:
    - sast_scan
  only:
    - main
  when: on_success  # Only deploy if previous stages succeed
```

## GitLab SAST Report Converter

```python
#!/usr/bin/env python3
# scripts/convert_to_gitlab_sast.py

import json
import sys
import argparse
from datetime import datetime

def convert_to_gitlab_sast(input_file, output_file):
    """Convert our JSON format to GitLab SAST format"""
    
    with open(input_file, 'r') as f:
        report = json.load(f)
    
    gitlab_report = {
        "version": "15.0.4",
        "vulnerabilities": [],
        "scan": {
            "analyzer": {
                "id": "secure-code-analyzer",
                "name": "Secure Code Analyzer",
                "version": "1.0.0",
                "vendor": {
                    "name": "Your Company"
                }
            },
            "scanner": {
                "id": "secure-code-analyzer",
                "name": "Secure Code Analyzer"
            },
            "type": "sast",
            "start_time": datetime.utcnow().isoformat() + "Z",
            "end_time": datetime.utcnow().isoformat() + "Z",
            "status": "success"
        }
    }
    
    # Convert findings to GitLab format
    for finding in report.get('findings', []):
        vulnerability = {
            "id": f"sca-{finding.get('rule_id', 'unknown')}-{finding.get('path', '')}-{finding.get('start', {}).get('line', 0)}",
            "category": "sast",
            "name": finding.get('message', 'Security Issue'),
            "description": finding.get('message', 'Security vulnerability detected'),
            "severity": finding.get('severity', '').title(),
            "confidence": "High",
            "scanner": {
                "id": "secure-code-analyzer",
                "name": "Secure Code Analyzer"
            },
            "location": {
                "file": finding.get('path', ''),
                "start_line": finding.get('start', {}).get('line', 1),
                "end_line": finding.get('end', {}).get('line', 1)
            },
            "identifiers": [
                {
                    "type": "sca_rule_id",
                    "name": finding.get('rule_id', 'unknown'),
                    "value": finding.get('rule_id', 'unknown')
                }
            ]
        }
        gitlab_report["vulnerabilities"].append(vulnerability)
    
    with open(output_file, 'w') as f:
        json.dump(gitlab_report, f, indent=2)
    
    print(f"Converted {len(gitlab_report['vulnerabilities'])} vulnerabilities to GitLab SAST format")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input JSON file")
    parser.add_argument("--output", required=True, help="Output GitLab SAST JSON file")
    
    args = parser.parse_args()
    convert_to_gitlab_sast(args.input, args.output)
```