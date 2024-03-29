import subprocess
import boto3
import os
import argparse


def get_temp_credentials(role_arn):
    # Initialize a session using the default credentials chain
    session = boto3.Session()
    # Get temporary credentials using STS assuming the role
    sts_client = session.client('sts')
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='AssumeRoleSession'
    )

    # Extract temporary credentials
    credentials = response['Credentials']
    aws_access_key_id = credentials['AccessKeyId']
    aws_secret_access_key = credentials['SecretAccessKey']
    aws_session_token = credentials['SessionToken']

    return aws_access_key_id, aws_secret_access_key, aws_session_token

def run_aws_command(aws_access_key_id, aws_secret_access_key, aws_session_token, command):
    # Set environment variables with temporary credentials
    os.environ['AWS_ACCESS_KEY_ID'] = aws_access_key_id
    os.environ['AWS_SECRET_ACCESS_KEY'] = aws_secret_access_key
    os.environ['AWS_SESSION_TOKEN'] = aws_session_token

    # Run AWS CLI command
    subprocess.run(command, shell=True)

    os.environ.pop('AWS_ACCESS_KEY_ID', None)
    os.environ.pop('AWS_SECRET_ACCESS_KEY', None)
    os.environ.pop('AWS_SESSION_TOKEN', None)


if __name__ == "__main__":
    # List of role ARNs to assume
    
    role_arns = ["arn:aws:iam::ACCOUNT#:role/ReadOnlyAccess","arn:aws:iam::ACCOUNT#:role/TestAdmin"]
        # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Assume roles and run AWS CLI commands')
    parser.add_argument('aws_command', type=str, help='AWS CLI command to run after assuming each role')
    args = parser.parse_args()
    # AWS CLI command to run after assuming each role
    aws_command = "aws sts get-caller-identity"
    
    # Loop through each role ARN
    for role_arn in role_arns:
        # Call the function to get temporary credentials for the current role
        aws_access_key_id, aws_secret_access_key, aws_session_token = get_temp_credentials(role_arn)
        
        # Run AWS CLI command using the assumed role
        run_aws_command(aws_access_key_id, aws_secret_access_key, aws_session_token, aws_command)

