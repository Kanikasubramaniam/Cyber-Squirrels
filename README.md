# IAM Policy Auditor

A Python tool for auditing IAM JSON policy files in cloud environments like AWS.

## Features

- Parses IAM policy JSON files
- Detects common security misconfigurations:
  - Wildcard permissions (`"*"`)
  - Overly broad actions
  - Missing conditions
  - Privilege escalation risks
  - Public access risks

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Command Line Interface (CLI)

```bash
# Audit a single policy file and print findings to console
python iam_auditor.py -f path/to/policy.json

# Audit all policy files in a directory
python iam_auditor.py -d path/to/policies/

# Generate a detailed report in Markdown format
python iam_auditor.py -d path/to/policies/ --report report.md
```

### Web API (Flask)

To use the Web API, first ensure Flask is installed (it's included in `requirements.txt`). Then run the Flask application:

```bash
python web_api.py
```

This will typically start a development server (e.g., on `http://127.0.0.1:5000/`).

You can then send a POST request with the IAM policy JSON file to the `/audit` endpoint. 

**Example using cURL:**

```bash
curl -X POST -F "file=@/path/to/your_policy.json" http://127.0.0.1:5000/audit
```

The API will return a JSON response containing the audit findings.

## Output

The tool provides a summary of findings with severity ratings and recommendations for remediation. 