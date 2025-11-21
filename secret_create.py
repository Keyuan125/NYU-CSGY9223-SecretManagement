import json
import boto3
import os
import string
import random
from botocore.exceptions import ClientError
"""
Example Input for testing:
{
  "SecretName": "test-secret-1",
  "SecretValue": "SuperSecretPassword12345!",
  "Description": "Test secret description",
  "KmsKeyId": "kms arn",
  "User": "admin"
  "Environment": "Testing"
}
"""

secrets_client = boto3.client("secretsmanager")
def generate_random_secret(length=32):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def apply_permissions(secret_name, permissions):
    """

    Working Input Example:
        {
        "SecretName": "1-test-password",
        "SecretValue": "Super-S3cret-Pa$$word1!",
        "Description": "Here is a testing value for test number 1",
        "Permissions": [
            {
            "RoleArn": "arn:aws:iam::1111111111:role/test-lambda-secret",
            "Actions": ["secretsmanager:GetSecretValue"]
            }
        ]
        }

        Also attached these permissions to the role for the lambda:

                    {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "VisualEditor0",
                        "Effect": "Allow",
                        "Action": [
                            "secretsmanager:GetResourcePolicy",
                            "secretsmanager:PutResourcePolicy"
                        ],
                        "Resource": "*"
                    }
                ]
            }
    """
    print("Existing policy:", secrets_client.get_resource_policy(SecretId=secret_name))

    if not permissions:
        print("No permissions to apply, exiting")
        return

    statements = []

    secret_policy_resource = "*"  # AWS requires "*" in resource policy

    for idx, p in enumerate(permissions):
        role_arn = p["RoleArn"]
        actions = p.get("Actions", ["secretsmanager:GetSecretValue"])

        statements.append({
            "Sid": f"Stmt{idx}",
            "Effect": "Allow",
            "Principal": {"AWS": role_arn},
            "Action": actions,
            "Resource": secret_policy_resource
        })

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": statements
    }
    print("Applying policy:", json.dumps(policy_doc, indent=2))
    secrets_client.put_resource_policy(
        SecretId=secret_name,
        ResourcePolicy=json.dumps(policy_doc)
    )


def lambda_handler(event, context):
    """
    Expected input (event):
    {
        "SecretName": "secret-name",
        "SecretValue": "optional_value"
        "Environment": "none",
        "User": "username",
        "KmsKeyId:": "Optional_kms_arn"
    }
    """
    secret_name = event.get("SecretName")
    if not secret_name:
        return {"statusCode": 400, "body": "Missing required field: SecretName"}
    kms_key_id = event.get("KmsKeyId", os.environ.get("DEFAULT_KMS_KEY_ID"))
    secret_value = event.get("SecretValue")
    description = event.get("Description")
    
    # generating a random secret if it isn't provided
    if not secret_value:
        secret_value = generate_random_secret()
    
    #default description if nothing is provide
    if not description:
        description = "Created via Lambda function"
    tags = [
        {"Key": "Environment", "Value": event.get("Environment", "Not specified")},
        {"Key": "CreatedBy", "Value": event.get("User", "Unknown")},
        {"Key": "ManagedBy", "Value": "SecretCLI"},
        {"Key": "SecretType", "Value": event.get("SecretType", "Generic")},
    ]
    def create_secret_with_keys(key_id=None):
        params = {
            "Name": secret_name,
            "SecretString": secret_value,
            "Description": description,
            "Tags": tags,
        }
        if key_id:
            params["KmsKeyId"] = key_id
        return secrets_client.create_secret(**params)
        # ran into some issues with this, it seems like there does need to be IAM permissions on the key itself. As a current workaround, I added checks to see if there are permissions
        # if kms_key_id:
        #     params["KmsKeyId"] = kms_key_id
        
        # response = secrets_client.create_secret(**params)
    
    try:
        try:
            response = create_secret_with_keys(kms_key_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                """
                The lambda function role needs to be added to the KMS key as a user, otherwise this will default
                """
                response = create_secret_with_keys(None)
            else:
                return {
                    "statusCode": 500,
                    "body": json.dumps({"Error": str(e)})
                }
        
        permissions = event.get("Permissions", [])
        apply_permissions(secret_name, permissions)
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "Message": f"Secret '{secret_name}' created successfully.",
                "ARN": response["ARN"],
                "Name": response["Name"],
                "KMSKey": kms_key_id,
                "Environment": event.get("Environment", "Not specified"),
                "Tags": response.get("Tags", []),
                "CreatedBy": event.get("User", "Unknown")
            })
        }
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceExistsException":
            return {
                "statusCode": 409,
                "body": json.dumps({"Error": f"Secret '{secret_name}' already exists."})
            }
        else:
            return {
                "statusCode": 500,
                "body": json.dumps({"Error": str(e)})
            }import json
import boto3
import os
import string
import random
from botocore.exceptions import ClientError
"""
Example Input for testing:
{
  "SecretName": "test-secret-1",
  "SecretValue": "SuperSecretPassword12345!",
  "Description": "Test secret description",
  "KmsKeyId": "kms arn",
  "User": "admin"
  "Environment": "Testing"
}
"""
secrets_client = boto3.client("secretsmanager")
def generate_random_secret(length=32):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))
def lambda_handler(event, context):
    """
    Expected input (event):
    {
        "SecretName": "secret-name",
        "SecretValue": "optional_value"
        "Environment": "none",
        "User": "username",
        "KmsKeyId:": "Optional_kms_arn"
    }
    """
    secret_name = event.get("SecretName")
    if not secret_name:
        return {"statusCode": 400, "body": "Missing required field: SecretName"}
    kms_key_id = event.get("KmsKeyId", os.environ.get("DEFAULT_KMS_KEY_ID"))
    secret_value = event.get("SecretValue")
    description = event.get("Description")
    
    # generating a random secret if it isn't provided
    if not secret_value:
        secret_value = generate_random_secret()
    
    #default description if nothing is provide
    if not description:
        description = "Created via Lambda function"
    tags = [
        {"Key": "Environment", "Value": event.get("Environment", "Not specified")},
        {"Key": "CreatedBy", "Value": event.get("User", "Unknown")},
        {"Key": "ManagedBy", "Value": "SecretCLI"},
        {"Key": "SecretType", "Value": event.get("SecretType", "Generic")},
    ]
    def create_secret_with_keys(key_id=None):
        params = {
            "Name": secret_name,
            "SecretString": secret_value,
            "Description": description,
            "Tags": tags,
        }
        if key_id:
            params["KmsKeyId"] = key_id
        return secrets_client.create_secret(**params)
        # ran into some issues with this, it seems like there does need to be IAM permissions on the key itself. As a current workaround, I added checks to see if there are permissions
        # if kms_key_id:
        #     params["KmsKeyId"] = kms_key_id
        
        # response = secrets_client.create_secret(**params)
    
    try:
        try:
            response = create_secret_with_keys(kms_key_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                response = create_secret_with_keys(None)
            else:
                return {
                    "statusCode": 500,
                    "body": json.dumps({"Error": str(e)})
                }
        return {
            "statusCode": 200,
            "body": json.dumps({
                "Message": f"Secret '{secret_name}' created successfully.",
                "ARN": response["ARN"],
                "Name": response["Name"],
                "KMSKey": kms_key_id,
                "Environment": event.get("Environment", "Not specified"),
                "Tags": response.get("Tags", []),
                "CreatedBy": event.get("User", "Unknown")
            })
        }
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceExistsException":
            return {
                "statusCode": 409,
                "body": json.dumps({"Error": f"Secret '{secret_name}' already exists."})
            }
        else:
            return {
                "statusCode": 500,
                "body": json.dumps({"Error": str(e)})
            }
