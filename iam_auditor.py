#!/usr/bin/env python3
"""
IAM Policy Auditor - A tool for auditing IAM policy files for security misconfigurations
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Any, Set, Tuple
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Import AWS-specific rules
try:
    from aws_rules import AwsIamRules
    HAS_AWS_RULES = True
except ImportError:
    HAS_AWS_RULES = False

# Import LLM Remediator
try:
    from llm_remediator import get_llm_suggestion, GEMINI_CLIENT_INITIALIZED
    HAS_LLM_REMEDIATOR = True
except ImportError:
    # print("LLM Remediator module not found. LLM suggestions will be disabled.")
    HAS_LLM_REMEDIATOR = False
    GEMINI_CLIENT_INITIALIZED = False # Ensure this is defined

console = Console()

class PolicyAuditor:
    """Analyze IAM policies for security misconfigurations"""
    
    def __init__(self, enable_llm_suggestions: bool = False):
        self.enable_llm_suggestions = enable_llm_suggestions
        if self.enable_llm_suggestions and not (HAS_LLM_REMEDIATOR and GEMINI_CLIENT_INITIALIZED):
            console.print("[yellow]Warning:[/] LLM suggestions enabled, but remediator module or API key is not available. Suggestions will be skipped.")
            self.enable_llm_suggestions = False # Disable if not usable

        # Define high-risk actions that can lead to privilege escalation
        self.high_risk_actions = {
            'iam:*',
            'iam:CreateAccessKey',
            'iam:CreatePolicyVersion',
            'iam:CreateLoginProfile',
            'iam:UpdateLoginProfile',
            'iam:AttachRolePolicy',
            'iam:AttachUserPolicy',
            'iam:AttachGroupPolicy',
            'iam:PutUserPolicy',
            'iam:PutRolePolicy',
            'iam:PutGroupPolicy',
            'lambda:CreateFunction',
            'lambda:InvokeFunction',
            'ec2:RunInstances',
            's3:PutObject'
        }
        
        # Define actions that could lead to public exposure if misconfigured
        self.public_exposure_actions = {
            's3:PutBucketPolicy',
            's3:PutBucketAcl',
            's3:PutObjectAcl',
            'ec2:AuthorizeSecurityGroupIngress',
            'ec2:ModifyInstanceAttribute',
            'rds:ModifyDBInstance',
            'lambda:AddPermission',
        }
        
        # Initialize AWS rules if available
        if HAS_AWS_RULES:
            self.aws_rules = AwsIamRules()
        
        # Define sensitive actions that should ideally have conditions
        self.sensitive_actions_requiring_conditions = {
            's3:DeleteObject',
            's3:DeleteBucket',
            's3:PutBucketPolicy',
            'ec2:TerminateInstances',
            'ec2:StopInstances',
            'iam:CreateUser',
            'iam:DeleteUser',
            'iam:CreateAccessKey',
            'iam:DeleteAccessKey',
            'iam:CreatePolicyVersion',
            'iam:DeletePolicy',
            'iam:UpdateAssumeRolePolicy',
            'rds:DeleteDBInstance',
            'lambda:DeleteFunction',
            'kms:ScheduleKeyDeletion',
            'kms:DisableKey'
        }
        
    def load_policy(self, policy_path: str) -> Dict[str, Any]:
        """Load IAM policy from a JSON file"""
        try:
            with open(policy_path, 'r') as f:
                policy_data = json.load(f)
            
            # Validate basic IAM policy structure
            if "Version" not in policy_data:
                console.print(f"[bold red]Error:[/] Missing 'Version' field in {policy_path}")
                return {}
            if "Statement" not in policy_data:
                console.print(f"[bold red]Error:[/] Missing 'Statement' field in {policy_path}")
                return {}
            
            return policy_data
            
        except json.JSONDecodeError:
            console.print(f"[bold red]Error:[/] {policy_path} is not a valid JSON file")
            return {}
        except FileNotFoundError:
            console.print(f"[bold red]Error:[/] File {policy_path} not found")
            return {}
    
    def audit_policy(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit an IAM policy for potential security issues"""
        findings = []
        
        if not policy:
            return findings
            
        # Extract policy statements
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
            
        for statement in statements:
            effect = statement.get("Effect", "")
            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])
            conditions = statement.get("Condition", {})
            
            # Convert single strings to lists for consistent processing
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
                
            # Skip if not an Allow statement (Deny statements are generally restrictive)
            if effect.lower() != "allow":
                continue
                
            # Check for wildcard actions
            if "*" in actions:
                findings.append({
                    "severity": "HIGH",
                    "category": "Wildcard Action",
                    "description": "Policy contains wildcard action '*' which grants excess permissions",
                    "recommendation": "Limit actions to only those needed for the specific use case",
                    "statement": statement
                })
            
            # Check for wildcard in action prefixes
            for action in actions:
                if action.endswith(":*"):
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "Broad Service Permissions",
                        "description": f"Policy grants all permissions for service: {action}",
                        "recommendation": "Limit to specific actions required for the service",
                        "statement": statement
                    })
            
            # Check for wildcard resources
            if "*" in resources:
                findings.append({
                    "severity": "HIGH",
                    "category": "Wildcard Resource",
                    "description": "Policy applies to all resources, violating principle of least privilege",
                    "recommendation": "Specify only the resources that need to be accessed",
                    "statement": statement
                })
            
            # Check for high-risk actions
            high_risk = [a for a in actions if a in self.high_risk_actions]
            if high_risk:
                findings.append({
                    "severity": "HIGH",
                    "category": "Privilege Escalation Risk",
                    "description": f"Policy contains high-risk actions: {', '.join(high_risk)}",
                    "recommendation": "Remove unnecessary privileged actions or add strict conditions",
                    "statement": statement
                })
            
            # Check for public exposure risks
            exposure_risk = [a for a in actions if a in self.public_exposure_actions]
            if exposure_risk and not conditions:
                findings.append({
                    "severity": "HIGH",
                    "category": "Public Exposure Risk",
                    "description": f"Policy allows actions that could expose resources publicly: {', '.join(exposure_risk)}",
                    "recommendation": "Add conditions to prevent public access",
                    "statement": statement
                })
            
            # Check for missing conditions on sensitive actions
            if any(a for a in actions if a.startswith("iam:")) and not conditions:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "Missing Conditions",
                    "description": "IAM actions without condition restrictions",
                    "recommendation": "Add conditions like MFA, source IP, or time-based restrictions",
                    "statement": statement
                })
            
            # Check for sensitive actions missing conditions
            found_sensitive_actions = [a for a in actions if a in self.sensitive_actions_requiring_conditions]
            if found_sensitive_actions and not conditions:
                finding = {
                    "severity": "MEDIUM", # Could be HIGH depending on the action
                    "category": "Sensitive Action Without Condition",
                    "description": f"Policy grants sensitive actions: {', '.join(found_sensitive_actions)} without any conditions.",
                    "recommendation": "Apply conditions like MFA, source IP restrictions, or time-based access for these actions.",
                    "statement": statement
                }
                findings.append(finding)
        
        # Run AWS-specific checks if available
        if HAS_AWS_RULES:
            findings.extend(self.aws_rules.check_for_privilege_escalation(policy))
            findings.extend(self.aws_rules.check_resource_exposure(policy))
            findings.extend(self.aws_rules.check_for_data_exfiltration(policy))
                
        # Process findings for LLM suggestions if enabled
        if self.enable_llm_suggestions:
            for finding in findings:
                # For now, let's try to get suggestions for HIGH and MEDIUM severity findings
                # that involve a specific statement.
                if finding.get("severity") in ["HIGH", "MEDIUM"] and "statement" in finding:
                    try:
                        statement_json_str = json.dumps(finding["statement"])
                        llm_suggestion_data = get_llm_suggestion(
                            statement_json_str,
                            finding["description"] # Pass the risk description
                        )
                        if llm_suggestion_data:
                            finding["llm_suggestion"] = llm_suggestion_data.get("suggested_statement")
                            finding["llm_explanation"] = llm_suggestion_data.get("explanation")
                    except Exception as e:
                        console.print(f"[red]Error getting LLM suggestion for a finding: {e}[/red]")

        return findings
    
    def audit_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Audit a single IAM policy file"""
        policy = self.load_policy(file_path)
        return self.audit_policy(policy)
    
    def audit_directory(self, dir_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """Audit all JSON files in a directory"""
        results = {}
        path = Path(dir_path)
        
        for file in path.glob("**/*.json"):
            findings = self.audit_file(str(file))
            if findings:
                results[str(file)] = findings
                
        return results
    
    def print_findings(self, findings: List[Dict[str, Any]], file_path: str = None):
        """Print findings in a formatted table"""
        if not findings:
            if file_path:
                console.print(f"[green]No issues found in {file_path}[/green]")
            else:
                console.print("[green]No issues found[/green]")
            return
            
        table = Table(title=f"Findings for {file_path}" if file_path else "Policy Findings")
        table.add_column("Severity", style="bold")
        table.add_column("Category")
        table.add_column("Description")
        table.add_column("Recommendation")
        if self.enable_llm_suggestions:
            table.add_column("LLM Suggestion", overflow="fold")
            table.add_column("LLM Explanation", overflow="fold")
        
        for finding in findings:
            severity_style = "red" if finding["severity"] == "HIGH" else "yellow" if finding["severity"] == "MEDIUM" else "blue"
            
            row_data = [
                f"[{severity_style}]{finding['severity']}[/{severity_style}]",
                finding["category"],
                finding["description"],
                finding["recommendation"]
            ]
            
            if self.enable_llm_suggestions:
                suggested_stmt_str = "N/A"
                if finding.get("llm_suggestion"):
                    try:
                        suggested_stmt_str = json.dumps(finding["llm_suggestion"], indent=2)
                    except TypeError: # If it's not serializable for some reason
                        suggested_stmt_str = str(finding["llm_suggestion"])
                row_data.append(suggested_stmt_str)
                row_data.append(finding.get("llm_explanation", "N/A"))
            
            table.add_row(*row_data)
            
        console.print(table)
    
    def generate_report(self, results: Dict[str, List[Dict[str, Any]]], output_file: str):
        """Generate a detailed report and save to file"""
        total_files = len(results)
        total_findings = sum(len(findings) for findings in results.values())
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for findings in results.values():
            for finding in findings:
                severity_counts[finding["severity"]] += 1
        
        with open(output_file, 'w') as f:
            f.write("# IAM Policy Audit Report\n\n")
            f.write(f"Files analyzed: {total_files}\n")
            f.write(f"Total findings: {total_findings}\n")
            f.write(f"HIGH severity findings: {severity_counts['HIGH']}\n")
            f.write(f"MEDIUM severity findings: {severity_counts['MEDIUM']}\n")
            f.write(f"LOW severity findings: {severity_counts['LOW']}\n\n")
            
            for file_path, findings in results.items():
                f.write(f"## {file_path}\n\n")
                if not findings:
                    f.write("No issues found.\n\n")
                    continue
                    
                f.write("| Severity | Category | Description | Recommendation |")
                if self.enable_llm_suggestions:
                     f.write(" LLM Suggested Statement | LLM Explanation |\n")
                else:
                    f.write("\n")
                
                f.write("|----------|----------|-------------|----------------|")
                if self.enable_llm_suggestions:
                    f.write("-------------------------|-----------------|\n")
                else:
                    f.write("\n")
                
                for finding in findings:
                    f.write(f"| {finding['severity']} | {finding['category']} | {finding['description']} | {finding['recommendation']} |")
                    if self.enable_llm_suggestions:
                        suggested_stmt_md = "N/A"
                        if finding.get("llm_suggestion"):
                            try:
                                # For Markdown, escape pipe characters and use code blocks for readability
                                suggested_stmt_md = f"```json\n{json.dumps(finding['llm_suggestion'], indent=2)}\n```".replace("|", "\\|")
                            except TypeError:
                                suggested_stmt_md = str(finding["llm_suggestion"]).replace("|","\\|")
                        explanation_md = finding.get("llm_explanation", "N/A").replace("|", "\\|")
                        f.write(f" {suggested_stmt_md} | {explanation_md} |\n")
                    else:
                        f.write("\n")
                f.write("\n")
                
        console.print(f"[green]Report saved to {output_file}[/green]")

def main():
    parser = argparse.ArgumentParser(description="Audit IAM policy files for security misconfigurations")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to a single policy file")
    group.add_argument("-d", "--directory", help="Path to a directory containing policy files")
    parser.add_argument("--report", help="Generate a detailed report and save to the specified file")
    parser.add_argument("--cloud", choices=["aws", "azure", "gcp"], default="aws", help="Cloud provider to audit (default: aws)")
    parser.add_argument("--enable-llm", action="store_true", help="Enable LLM-based suggestions for remediations (requires GOOGLE_API_KEY)")
    
    args = parser.parse_args()
    auditor = PolicyAuditor(enable_llm_suggestions=args.enable_llm)
    
    console.print(Panel.fit("IAM Policy Auditor", title="Security Audit Tool"))
    
    if args.cloud != "aws" and HAS_AWS_RULES:
        console.print(f"[yellow]Warning: Only AWS rules are currently implemented. Using AWS rules for {args.cloud}.[/yellow]")
    elif args.cloud != "aws" and not HAS_AWS_RULES:
        console.print(f"[yellow]Warning: Rules for {args.cloud} are not implemented. Using generic rules only.[/yellow]")
    
    if args.file:
        file_path = args.file
        findings = auditor.audit_file(file_path)
        auditor.print_findings(findings, file_path)
        
        if args.report and findings:
            auditor.generate_report({file_path: findings}, args.report)
            
    elif args.directory:
        dir_path = args.directory
        results = auditor.audit_directory(dir_path)
        
        if not results:
            console.print("[yellow]No policy files with issues found in the directory[/yellow]")
        else:
            console.print(f"[bold]Found issues in {len(results)} files[/bold]")
            for file_path, findings in results.items():
                auditor.print_findings(findings, file_path)
                
        if args.report:
            auditor.generate_report(results, args.report)

if __name__ == "__main__":
    main() 