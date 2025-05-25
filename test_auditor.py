#!/usr/bin/env python3
"""
Unit tests for the IAM Policy Auditor
"""

import unittest
import json
from iam_auditor import PolicyAuditor
from aws_rules import AwsIamRules

class TestPolicyAuditor(unittest.TestCase):
    """Test cases for the IAM Policy Auditor"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.auditor = PolicyAuditor()
        self.aws_rules = AwsIamRules()
        
        # Load sample policies for testing
        with open("samples/admin_policy.json", "r") as f:
            self.admin_policy = json.load(f)
            
        with open("samples/s3_policy.json", "r") as f:
            self.s3_policy = json.load(f)
            
        with open("samples/ec2_policy.json", "r") as f:
            self.ec2_policy = json.load(f)
            
        with open("samples/secure_policy.json", "r") as f:
            self.secure_policy = json.load(f)
            
        with open("samples/sensitive_actions_no_conditions_policy.json", "r") as f:
            self.sensitive_actions_policy = json.load(f)
    
    def test_wildcard_detection(self):
        """Test detection of wildcard permissions"""
        findings = self.auditor.audit_policy(self.admin_policy)
        
        # Check for wildcard action detection
        wildcard_findings = [f for f in findings if f["category"] == "Wildcard Action"]
        self.assertTrue(len(wildcard_findings) > 0, "Failed to detect wildcard action")
        
        # Check for wildcard resource detection
        resource_findings = [f for f in findings if f["category"] == "Wildcard Resource"]
        self.assertTrue(len(resource_findings) > 0, "Failed to detect wildcard resource")
    
    def test_service_wildcard_detection(self):
        """Test detection of service-level wildcard permissions"""
        findings = self.auditor.audit_policy(self.s3_policy)
        
        # Check for service wildcard detection (s3:*)
        service_wildcard_findings = [f for f in findings if f["category"] == "Broad Service Permissions"]
        self.assertTrue(len(service_wildcard_findings) > 0, "Failed to detect service-level wildcard")
    
    def test_public_exposure_risk(self):
        """Test detection of actions that can lead to public exposure"""
        findings = self.auditor.audit_policy(self.s3_policy)
        
        # Check for public exposure risk detection
        exposure_findings = [f for f in findings if f["category"] == "Public Exposure Risk"]
        self.assertTrue(len(exposure_findings) > 0, "Failed to detect public exposure risk")
    
    def test_secure_policy(self):
        """Test that secure policies don't generate findings"""
        findings = self.auditor.audit_policy(self.secure_policy)
        
        # Secure policy should not have high severity findings
        high_severity = [f for f in findings if f["severity"] == "HIGH"]
        self.assertEqual(len(high_severity), 0, "Secure policy generated high severity findings")
    
    def test_aws_privilege_escalation(self):
        """Test AWS-specific privilege escalation checks"""
        findings = self.aws_rules.check_for_privilege_escalation(self.admin_policy)
        
        # Admin policy should be flagged for privilege escalation
        self.assertTrue(len(findings) > 0, "Failed to detect privilege escalation risk")
    
    def test_aws_resource_exposure(self):
        """Test AWS-specific resource exposure checks"""
        findings = self.aws_rules.check_resource_exposure(self.s3_policy)
        
        # S3 policy with PutBucketPolicy should be flagged
        self.assertTrue(len(findings) > 0, "Failed to detect resource exposure risk")
    
    def test_audit_file(self):
        """Test auditing a file directly"""
        findings = self.auditor.audit_file("samples/admin_policy.json")
        
        # Admin policy should have findings
        self.assertTrue(len(findings) > 0, "Failed to detect issues in admin policy file")
        
    def test_audit_directory(self):
        """Test auditing a directory of policy files"""
        results = self.auditor.audit_directory("samples")
        
        # There should be findings for at least 3 files (admin, s3, ec2)
        self.assertTrue(len(results) >= 3, "Failed to properly audit directory")
    
    def test_invalid_policy_structure(self):
        """Test loading policies with invalid structure (missing Version or Statement)"""
        # Test policy missing "Version"
        policy_missing_version = self.auditor.load_policy("samples/missing_version_policy.json")
        self.assertEqual(policy_missing_version, {}, "Policy missing 'Version' should return empty dict")

        # Test policy missing "Statement"
        policy_missing_statement = self.auditor.load_policy("samples/missing_statement_policy.json")
        self.assertEqual(policy_missing_statement, {}, "Policy missing 'Statement' should return empty dict")
    
    def test_sensitive_actions_without_conditions(self):
        """Test detection of sensitive actions granted without conditions."""
        findings = self.auditor.audit_policy(self.sensitive_actions_policy)
        sensitive_action_findings = [f for f in findings if f["category"] == "Sensitive Action Without Condition"]
        self.assertTrue(len(sensitive_action_findings) > 0, "Failed to detect sensitive actions without conditions.")
        # Ensure the specific actions are mentioned
        self.assertIn("s3:DeleteObject", sensitive_action_findings[0]["description"])
        self.assertIn("ec2:TerminateInstances", sensitive_action_findings[0]["description"])
        self.assertIn("iam:DeleteUser", sensitive_action_findings[0]["description"])

if __name__ == "__main__":
    unittest.main() 