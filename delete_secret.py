# -----------------------------------------------------------------------------
# Secret Deletion Script
# This AWS Lambda function deletes a specified secret from AWS Secrets Manager.
# It supports both soft deletion (with a recovery window) and immediate permanent
# deletion (force delete). The function expects a JSON event input containing
# the secret name or ARN and an optional flag to force delete.
#
# Example Event Input:
# {
#   "SecretId": "prod/backend/api-key",
#   "ForceDelete": false
# }
#
# Behavior:
# - If ForceDelete = false → secret enters scheduled deletion (default 7-day recovery).
# - If ForceDelete = true → secret is permanently deleted immediately.
# -----------------------------------------------------------------------------

import json
import boto3
from botocore.exceptions import ClientError

# Initialize AWS Secrets Manager client
secrets_client = boto3.client("secretsmanager")

def lambda_handler(event, context):
    """
    Lambda entry point for deleting a secret.

    Args:
        event (dict): Expected input format:
            {
              "SecretId": "secret-name-or-arn",
              "ForceDelete": true|false
            }
        context: AWS Lambda context (unused)
    """
    secret_id = event.get("SecretId")
    force_delete = bool(event.get("ForceDelete", False))

    if not secret_id:
        return {
            "statusCode": 400,
            "body": json.dumps({"Error": "Missing required field: SecretId"})
        }

    try:
        if force_delete:
            # Immediate permanent deletion
            response = secrets_client.delete_secret(
                SecretId=secret_id,
                ForceDeleteWithoutRecovery=True
            )
        else:
            # Scheduled deletion with recovery window
            response = secrets_client.delete_secret(
                SecretId=secret_id,
                RecoveryWindowInDays=7
            )

        return {
            "statusCode": 200,
            "body": json.dumps({
                "Message": f"Secret '{secret_id}' scheduled for deletion.",
                "DeletionDate": str(response.get("DeletionDate")),
                "ForceDelete": force_delete
            })
        }

    except ClientError as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"Error": str(e)})
        }
