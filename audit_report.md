# IAM Policy Audit Report

Files analyzed: 4
Total findings: 15
HIGH severity findings: 9
MEDIUM severity findings: 6
LOW severity findings: 0

## samples\admin_policy.json

| Severity | Category | Description | Recommendation |
|----------|----------|-------------|----------------|
| HIGH | Wildcard Action | Policy contains wildcard action '*' which grants excess permissions | Limit actions to only those needed for the specific use case |
| HIGH | Wildcard Resource | Policy applies to all resources, violating principle of least privilege | Specify only the resources that need to be accessed |
| HIGH | Privilege Escalation | Policy allows actions that can lead to privilege escalation: * | Restrict these permissions or add strict conditions |

## samples\ec2_policy.json

| Severity | Category | Description | Recommendation |
|----------|----------|-------------|----------------|
| HIGH | Wildcard Resource | Policy applies to all resources, violating principle of least privilege | Specify only the resources that need to be accessed |
| MEDIUM | Sensitive Action Without Condition | Policy grants sensitive actions: ec2:StopInstances without any conditions. | Apply conditions like MFA, source IP restrictions, or time-based access for these actions. |
| HIGH | Public Exposure Risk | Policy allows actions that could expose resources publicly: ec2:AuthorizeSecurityGroupIngress | Add conditions to prevent public access |
| HIGH | Public Resource Exposure | Policy allows actions that can expose resources publicly without restrictions: ec2:AuthorizeSecurityGroupIngress | Add conditions to prevent public access or restrict resource ARNs |

## samples\s3_policy.json

| Severity | Category | Description | Recommendation |
|----------|----------|-------------|----------------|
| MEDIUM | Broad Service Permissions | Policy grants all permissions for service: s3:* | Limit to specific actions required for the service |
| HIGH | Public Exposure Risk | Policy allows actions that could expose resources publicly: s3:PutBucketPolicy | Add conditions to prevent public access |
| MEDIUM | Sensitive Action Without Condition | Policy grants sensitive actions: s3:PutBucketPolicy without any conditions. | Apply conditions like MFA, source IP restrictions, or time-based access for these actions. |
| HIGH | Public Resource Exposure | Policy allows actions that can expose resources publicly without restrictions: s3:PutBucketPolicy | Add conditions to prevent public access or restrict resource ARNs |

## samples\sensitive_actions_no_conditions_policy.json

| Severity | Category | Description | Recommendation |
|----------|----------|-------------|----------------|
| HIGH | Wildcard Resource | Policy applies to all resources, violating principle of least privilege | Specify only the resources that need to be accessed |
| MEDIUM | Missing Conditions | IAM actions without condition restrictions | Add conditions like MFA, source IP, or time-based restrictions |
| MEDIUM | Sensitive Action Without Condition | Policy grants sensitive actions: s3:DeleteObject, ec2:TerminateInstances, iam:DeleteUser without any conditions. | Apply conditions like MFA, source IP restrictions, or time-based access for these actions. |
| MEDIUM | Data Exfiltration Risk | Policy allows actions that can lead to data exfiltration: s3:GetObject | Limit resource scope and add appropriate conditions |

