
# IAM User Management and Cleanup System

Our AWS IAM user management system provides comprehensive visibility and control over IAM users across an entire AWS organization. The solution operates in two distinct modes controlled by a "deleteFlag" parameter, enabling both inventory collection and targeted user cleanup.

In inventory mode (deleteFlag=False), the system connects to the management account and systematically traverses all member accounts using cross-account role assumption. For each account, it collects detailed IAM user information including usernames, IDs, creation dates, console access status, MFA configuration, and group memberships. This comprehensive inventory is compiled into a CSV report and automatically uploaded to a designated S3 bucket, providing security teams with a complete view of IAM users across the organization.

For cleanup operations (deleteFlag=True), the system leverages the previously generated inventory stored in S3. Security administrators can review this inventory and mark specific users for deletion by adding a "DeleteFlag" column and entering "yes" for targeted users. Once this modified CSV is uploaded back to the S3 bucket, the system processes it by identifying all users marked for deletion. For each flagged user, the system performs a thorough cleanup process - removing access keys, login profiles, detaching policies, removing group memberships, deactivating MFA devices, and deleting certificates and SSH keys - before finally removing the user account itself. This methodical approach ensures no orphaned resources remain after user deletion. The entire process is documented in a detailed deletion report that captures success status and any encountered issues, providing a complete audit trail of the cleanup operation.

This dual-mode system enables organizations to maintain accurate IAM user inventories while providing a controlled, documented process for user cleanup across complex multi-account AWS environments.
