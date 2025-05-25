"""
AWS IAM Policy Rules - Specific rules for AWS IAM policy auditing
"""

from typing import Dict, List, Any, Set

class AwsIamRules:
    """AWS-specific IAM policy rules and checks"""
    
    @staticmethod
    def get_dangerous_managed_policies() -> Set[str]:
        """Return a set of dangerous AWS managed policies that should be avoided"""
        return {
            "AdministratorAccess",
            "PowerUserAccess",
            "IAMFullAccess"
        }
    
    @staticmethod
    def check_for_privilege_escalation(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potential privilege escalation paths in AWS IAM policies"""
        findings = []
        privilege_escalation_actions = {
            'iam:CreateAccessKey',
            'iam:CreateLoginProfile',
            'iam:UpdateLoginProfile',
            'iam:AttachRolePolicy',
            'iam:AttachUserPolicy',
            'iam:PutUserPolicy',
            'lambda:CreateFunction',
            'lambda:InvokeFunction',
            'lambda:UpdateFunctionCode',
            'cloudformation:CreateStack',
            'cloudformation:UpdateStack',
            'ec2:RunInstances',
            'iam:PassRole'
        }
        
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
            
        for statement in statements:
            effect = statement.get("Effect", "")
            actions = statement.get("Action", [])
            
            if isinstance(actions, str):
                actions = [actions]
                
            if effect.lower() != "allow":
                continue
                
            risky_actions = [a for a in actions if a in privilege_escalation_actions or a == "iam:*" or a == "*"]
            
            if risky_actions:
                finding = {
                    "severity": "HIGH",
                    "category": "Privilege Escalation",
                    "description": f"Policy allows actions that can lead to privilege escalation: {', '.join(risky_actions)}",
                    "recommendation": "Restrict these permissions or add strict conditions",
                    "statement": statement
                }
                findings.append(finding)
                
        return findings
    
    @staticmethod
    def check_resource_exposure(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for policies that might allow exposing resources publicly"""
        findings = []
        public_exposure_actions = {
            's3:PutBucketPolicy',
            's3:PutBucketAcl',
            's3:PutObjectAcl',
            'ec2:AuthorizeSecurityGroupIngress',
            'lambda:AddPermission',
            'kms:PutKeyPolicy',
            'secretsmanager:PutResourcePolicy',
            'sns:AddPermission',
            'sqs:AddPermission'
        }
        
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
            
        for statement in statements:
            effect = statement.get("Effect", "")
            actions = statement.get("Action", [])
            conditions = statement.get("Condition", {})
            
            if isinstance(actions, str):
                actions = [actions]
                
            if effect.lower() != "allow":
                continue
                
            risky_actions = [a for a in actions if a in public_exposure_actions]
            
            # Check if there are any conditions that might restrict public access
            has_restriction = False
            if conditions:
                # Look for common conditions that restrict public access
                for condition_type, condition_values in conditions.items():
                    if condition_type in ["StringEquals", "ArnEquals", "IpAddress"]:
                        has_restriction = True
                        break
            
            if risky_actions and not has_restriction:
                finding = {
                    "severity": "HIGH",
                    "category": "Public Resource Exposure",
                    "description": f"Policy allows actions that can expose resources publicly without restrictions: {', '.join(risky_actions)}",
                    "recommendation": "Add conditions to prevent public access or restrict resource ARNs",
                    "statement": statement
                }
                findings.append(finding)
                
        return findings
        
    @staticmethod
    def check_for_data_exfiltration(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for policies that might allow data exfiltration"""
        findings = []
        data_exfiltration_actions = {
            's3:GetObject',
            's3:CopyObject',
            'dynamodb:GetItem',
            'dynamodb:Scan',
            'dynamodb:Query',
            'rds:CopyDBSnapshot',
            'rds:CreateDBSnapshot',
            'secretsmanager:GetSecretValue',
            'ssm:GetParameter',
            'ssm:GetParameters',
            'ec2:CreateSnapshot',
            'ec2:GetPasswordData'
        }
        
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
            
        for statement in statements:
            effect = statement.get("Effect", "")
            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])
            conditions = statement.get("Condition", {})
            
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
                
            if effect.lower() != "allow":
                continue
                
            risky_actions = [a for a in actions if a in data_exfiltration_actions]
            
            # Check if resources use wildcards
            has_wildcard_resources = any("*" in r for r in resources)
            
            if risky_actions and has_wildcard_resources and not conditions:
                finding = {
                    "severity": "MEDIUM",
                    "category": "Data Exfiltration Risk",
                    "description": f"Policy allows actions that can lead to data exfiltration: {', '.join(risky_actions)}",
                    "recommendation": "Limit resource scope and add appropriate conditions",
                    "statement": statement
                }
                findings.append(finding)
                
        return findings 