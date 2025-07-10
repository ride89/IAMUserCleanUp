import json
import boto3
import csv
from datetime import datetime
import time
from botocore.exceptions import ClientError
import os
import io


def get_organization_accounts():
    """Get all accounts in the organization from the management account"""
    try:
        org_client = boto3.client('organizations')
        accounts = []
        
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page['Accounts']:
                if account['Status'] == 'ACTIVE':
                    accounts.append({
                        'Id': account['Id'],
                        'Name': account['Name'],
                        'Email': account['Email']
                    })
        
        return accounts
    except Exception as e:
        print(f"Error retrieving organization accounts: {str(e)}")
        return []

def get_session():
    return boto3.Session()

def assume_role(session, account_id, role_name='OrganizationAccountAccessRole'):
    """Assume role in member account with proper error handling and debugging"""
    sts_client = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'

    try:
        print(f"  Attempting to assume role: {role_arn}")
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f'IAMUserInventory-{int(time.time())}',
            DurationSeconds=900  # 15 minutes
        )
        print(f"  Successfully assumed role in account {account_id}")
        return response['Credentials']
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        error_msg = e.response.get('Error', {}).get('Message', '')
        return None

def get_user_details(session, account_id, account_name=None, credentials=None):
    """Get details for all IAM users in an account"""
    try:
        if credentials:
            iam_client = session.client(
                'iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            print(f"  Using assumed role credentials for account {account_id}")
        else:
            # For management account, use default credentials
            iam_client = session.client('iam')
            print(f"  Using default credentials for account {account_id} (management account)")

        users = []
        
        # Get all users
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                
                user_data = {
                    'AccountId': account_id,
                    'AccountName': account_name or 'N/A',
                    'UserName': user['UserName'],
                    'UserId': user['UserId'],
                    'CreateDate': user['CreateDate'].strftime('%Y-%m-%d')
                }
                
                # Get user's MFA devices
                mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])
                try:
                    iam_client.get_login_profile(UserName=user['UserName'])
                    console_access = True
                except Exception as e:
                    console_access = False

                user_data['MFAEnabled'] = len(mfa_devices['MFADevices']) > 0
                user_data['ConsoleAccess'] = console_access
                
                users.append(user_data)
                
        return users
    except Exception as e:
        print(f"Error getting users for account {account_id}: {str(e)}")
        return []

def export_to_csv(users, filename):
    """Export user details to CSV file"""
    if not users:
        print("No user data to export")
        return
    
    # Flatten the user data for CSV export
    flattened_users = []
    for user in users:
        account_id = f"'{user['AccountId']}'"
        base_user = {
            'AccountId': account_id,
            'AccountName': user.get('AccountName', 'N/A'),
            'UserName': user['UserName'],
            'UserId': user['UserId'],
            'CreateDate': user['CreateDate'],
            'MFAEnabled': user.get('MFAEnabled', False),
            'ConsoleAccess': user.get('ConsoleAccess')
        }
        flattened_users.append(base_user)

    
    # Write to CSV
    fieldnames = ['AccountId', 'AccountName', 'UserName', 'UserId', 'CreateDate', 'MFAEnabled','ConsoleAccess']
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flattened_users)
    
    print(f"Data exported to {filename}")

def upload_to_s3(file_path, bucket_name, object_key=None):
    """Upload a file to S3"""
    try:
        s3_client = boto3.client('s3')
        s3_client.upload_file(file_path, bucket_name, object_key)
        return f"s3://{bucket_name}/{object_key}"
    except Exception as e:
        print(f"Error uploading to S3: {str(e)}")
        return None

def delete_iam_user(account_id, username, session, credentials):
    iam_client = session.client('iam', 
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'])
    try:
        # 1. List and delete access keys
        try:
            keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in keys:
                key_id = key['AccessKeyId']
                iam_client.delete_access_key(UserName=username, AccessKeyId=key_id)
                print(f"  - Deleted access key {key_id} for user {username}")
        except ClientError as e:
            print(f"  - Error deleting access keys for user {username}: {e}")

        # 2. List and delete login profile (console access)
        try:
            iam_client.get_login_profile(UserName=username)
            iam_client.delete_login_profile(UserName=username)
            print(f"  - Deleted login profile for user {username}")
        except ClientError as e:
            if "NoSuchEntity" not in str(e):
                print(f"  - Error deleting login profile for user {username}: {e}")

        # 3. List and detach user policies
        try:
            attached_policies = iam_client.list_attached_user_policies(UserName=username)['AttachedPolicies']
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                iam_client.detach_user_policy(UserName=username, PolicyArn=policy_arn)
                print(f"  - Detached policy {policy_arn} from user {username}")
        except ClientError as e:
            print(f"  - Error detaching policies for user {username}: {e}")

        # 4. List and delete inline policies
        try:
            inline_policies = iam_client.list_user_policies(UserName=username)['PolicyNames']
            for policy_name in inline_policies:
                iam_client.delete_user_policy(UserName=username, PolicyName=policy_name)
                print(f"  - Deleted inline policy {policy_name} from user {username}")
        except ClientError as e:
            print(f"  - Error deleting inline policies for user {username}: {e}")

        # 5. List and remove user from groups
        try:
            groups = iam_client.list_groups_for_user(UserName=username)['Groups']
            for group in groups:
                group_name = group['GroupName']
                iam_client.remove_user_from_group(GroupName=group_name, UserName=username)
                print(f"  - Removed user {username} from group {group_name}")
        except ClientError as e:
            print(f"  - Error removing user from groups: {e}")

        # 6. List and delete MFA devices
        try:
            mfa_devices = iam_client.list_mfa_devices(UserName=username)['MFADevices']
            for device in mfa_devices:
                device_serial = device['SerialNumber']
                iam_client.deactivate_mfa_device(UserName=username, SerialNumber=device_serial)
                print(f"  - Deactivated MFA device {device_serial} for user {username}")
        except ClientError as e:
            print(f"  - Error deactivating MFA devices: {e}")

        # 7. List and delete signing certificates
        try:
            certificates = iam_client.list_signing_certificates(UserName=username)['Certificates']
            for cert in certificates:
                cert_id = cert['CertificateId']
                iam_client.delete_signing_certificate(UserName=username, CertificateId=cert_id)
                print(f"  - Deleted signing certificate {cert_id} for user {username}")
        except ClientError as e:
            print(f"  - Error deleting signing certificates: {e}")

        # 8. List and delete SSH public keys
        try:
            ssh_keys = iam_client.list_ssh_public_keys(UserName=username)['SSHPublicKeys']
            for key in ssh_keys:
                key_id = key['SSHPublicKeyId']
                iam_client.delete_ssh_public_key(UserName=username, SSHPublicKeyId=key_id)
                print(f"  - Deleted SSH public key {key_id} for user {username}")
        except ClientError as e:
            print(f"  - Error deleting SSH public keys: {e}")

        # 9. List and delete service-specific credentials
        try:
            # For services like CodeCommit
            service_creds = iam_client.list_service_specific_credentials(UserName=username)['ServiceSpecificCredentials']
            for cred in service_creds:
                service_name = cred['ServiceName']
                cred_id = cred['ServiceSpecificCredentialId']
                iam_client.delete_service_specific_credential(UserName=username, ServiceSpecificCredentialId=cred_id)
                print(f"  - Deleted {service_name} credentials for user {username}")
        except ClientError as e:
            if "NoSuchEntity" not in str(e):
                print(f"  - Error deleting service-specific credentials: {e}")

        # 10. Finally delete the user
        iam_client.delete_user(UserName=username)
        print(f"  - Successfully deleted user {username} from account {account_id}")

    except ClientError as e:
        error_message = f"Failed to delete user {username} from account {account_id}: {e}"
        print(f"  - {error_message}")

def delete_user(session,bucket_name, filename):
    s3_client = session.client('s3')
    users_to_delete = []
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=filename)
        csv_content = response['Body'].read().decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(csv_content))
        
        # identify users to delete
        for row in csv_reader:
            username = row['UserName']
            userid = row['UserId']
            account_id = row['AccountId']
            delete_flag = row['DeleteFlag']
            
            if delete_flag == 'yes':
                users_to_delete.append({
                    'username': username,
                    'userid': userid,
                    'account_id': account_id
                })
        print(f"Found {len(users_to_delete)} users to delete")

        # Second pass: delete users
        for i, user in enumerate(users_to_delete):
            username = user['username']
            userid = user['userid']
            account_id = user['account_id']
            
            if account_id.startswith("'"):
                account_id = account_id[1:-1]

            credentials = assume_role(session,account_id)
            delete_iam_user(account_id, username, session, credentials)

    except Exception as e:
        print(f"Error deleting user: {str(e)}")
        return None

def lambda_handler(event, context):
    
    filename ="/tmp/iam_users_user_detail.csv"  
    bucket_name = "<BUKCET_NAME>"
    delete_user_flag = False
    session = get_session()

    if delete_user_flag:
        delete_user(session,bucket_name, os.path.basename(filename))
    else:
    # Get management account ID
        sts_client = boto3.client('sts')
        management_account_id = sts_client.get_caller_identity()['Account']
        print(f"Running from Management Account: {management_account_id}")
        
        # Get all accounts from Organizations service
        all_accounts = get_organization_accounts()
        print(f"Found {len(all_accounts)} accounts in the organization")

        management_account = next((acc for acc in all_accounts if acc['Id'] == management_account_id), None)
        member_accounts = [acc for acc in all_accounts if acc['Id'] != management_account_id]

        all_users = []
        
        if management_account:
            management_account_name = management_account['Name']
            management_users = get_user_details(session, management_account_id, management_account_name)
            all_users.extend(management_users)       
        
        # Process member accounts
        for account in member_accounts:
            print(f"Processing account: {account['Name']} ({account['Id']})")
            credentials = assume_role(session, account['Id'])
            if credentials:
                # Get IAM users using the assumed role
                users = get_user_details(session, account['Id'], account['Name'], credentials)
                all_users.extend(users)
            else:
                print(f"  Skipping account {account_id} due to role assumption failure")

        
        export_to_csv(all_users,filename)
        upload_to_s3(filename, bucket_name,os.path.basename(filename))
        print(f"Total users found across all accounts: {len(all_users)}")

    

