# -----------------------------------------------------------------------------
# Secret Descriptor Script
# This Python script simulates accessing a cloud secrets manager to retrieve
# only the metadata (Name, ARN, Description) for a specified secret,
# ensuring the sensitive value itself is never exposed.
# -----------------------------------------------------------------------------

# --- Simulated Cloud Environment Data ---
# This data mirrors the SECRET_DATA defined in the web agent's environment.
SECRET_DATA = [
    {
        "name": "prod/backend/api-key",
        "arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/backend/api-key",
        "description": "API Key for production microservices communication."
    },
    {
        "name": "dev/db/user-credentials",
        "arn": "arn:aws:secretsmanager:us-east-2:987654321098:secret:dev/db/user-credentials",
        "description": "Read/Write credentials for the development database cluster."
    },
    {
        "name": "staging/stripe/webhook-key",
        "arn": "arn:aws:secretsmanager:eu-west-1:112233445566:secret:staging/stripe/webhook-key",
        "description": "Stripe webhook signing secret for staging environment."
    },
    {
        "name": "Lambda script",
        "arn": "arn:aws:secretsmanager:ap-southeast-2:555544443333:secret:automation/lambda/script-token",
        "description": "Execution token used by the nightly Lambda job for cross-service calls."
    }
]

def describe_secret_metadata(secret_name: str) -> dict:
    """
    Simulates fetching the metadata for a secret by its name.

    Args:
        secret_name: The name of the secret to retrieve metadata for.

    Returns:
        A dictionary containing the secret's metadata, or an error message.
    """
    # Normalize input for case-insensitive search, similar to the JavaScript implementation
    normalized_name = secret_name.lower()

    for secret in SECRET_DATA:
        if secret["name"].lower() == normalized_name:
            # Return the metadata dictionary (excluding the sensitive value, which is not stored here)
            return {
                "Status": "Success",
                "Metadata": {
                    "Name": secret["name"],
                    "ARN": secret["arn"],
                    "Description": secret["description"]
                }
            }

    return {
        "Status": "Error",
        "Message": f"Secret '{secret_name}' not found in the simulated vault."
    }

# --- Execution ---
SECRET_TO_DESCRIBE = "Lambda script"
print(f"--- Requesting Metadata for Secret: {SECRET_TO_DESCRIBE} ---")

result = describe_secret_metadata(SECRET_TO_DESCRIBE)

if result["Status"] == "Success":
    metadata = result["Metadata"]
    print("\n[Audit Successful: Only Metadata Retrieved]")
    print(f"Name:        {metadata['Name']}")
    print(f"ARN:         {metadata['ARN']}")
    print(f"Description: {metadata['Description']}")
else:
    print(f"\n{result['Status']}: {result['Message']}")