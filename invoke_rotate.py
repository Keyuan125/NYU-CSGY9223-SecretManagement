import json
import os
import logging
import secrets
import string
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sm = boto3.client("secretsmanager")

def _gen_password(length=32, exclude_punctuation=True, require_each_type=True):
    # Build alphabet
    letters = string.ascii_letters
    digits = string.digits
    punctuation = "" if exclude_punctuation else string.punctuation

    alphabet = letters + digits + punctuation
    if length < 8:
        length = 8

    if not require_each_type:
        return "".join(secrets.choice(alphabet) for _ in range(length))

    # Ensure at least one of each category (letters/digits[/punctuation])
    must = [
        secrets.choice(letters),
        secrets.choice(digits),
    ]
    if punctuation:
        must.append(secrets.choice(punctuation))

    remaining = length - len(must)
    pool = [secrets.choice(alphabet) for _ in range(remaining)]
    pwd_list = must + pool
    secrets.SystemRandom().shuffle(pwd_list)
    return "".join(pwd_list)

def _describe(secret_id):
    return sm.describe_secret(SecretId=secret_id)

def _rotate_now(secret_id):
    # Calls Secrets Manager's rotation workflow; requires RotationEnabled & RotationLambdaARN on the secret
    return sm.rotate_secret(SecretId=secret_id, RotateImmediately=True)

def _put_value(secret_id, secret_string):
    # Creates a new version labeled AWSCURRENT; moves previous to AWSPREVIOUS automatically
    return sm.put_secret_value(SecretId=secret_id, SecretString=secret_string, VersionStages=["AWSCURRENT"])

def _ok(body, code=200):
    return {"statusCode": code, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body)}

def _err(msg, code=400):
    return _ok({"error": msg}, code)

def rotate_secret_handler(event, context):
    """
    Event JSON (Lambda proxy or direct invoke):
    {
      "secret_id": "my/secret/id or ARN",        # required
      "mode": "auto|trigger|set",                # optional (default: auto)
      "new_value": "{...}" or "string",          # optional (used when mode=set)
      "generate_random": true|false,             # optional (ignored if new_value provided)
      "random_length": 32,                       # optional
      "exclude_punctuation": true|false,         # optional
      "require_each_type": true|false            # optional
    }
    Behavior:
      - mode=trigger : call Secrets Manager rotate_secret (secret must have RotationLambda configured)
      - mode=set     : put a new secret value (uses new_value or generated)
      - mode=auto    : if RotationEnabled -> trigger; else set (generate or use new_value)
    """

    # Support API Gateway/Lambda URLs (proxy) and direct invoke
    if isinstance(event, dict) and "body" in event and isinstance(event["body"], str):
        try:
            payload = json.loads(event["body"])
        except json.JSONDecodeError:
            return _err("Invalid JSON in body")
    else:
        payload = event if isinstance(event, dict) else {}

    secret_id = payload.get("secret_id")
    if not secret_id:
        return _err("Missing required parameter: secret_id")

    mode = (payload.get("mode") or "auto").lower()
    new_value = payload.get("new_value")
    generate_random = bool(payload.get("generate_random", False))
    random_length = int(payload.get("random_length", 32))
    exclude_punc = bool(payload.get("exclude_punctuation", True))
    require_each_type = bool(payload.get("require_each_type", True))

    try:
        desc = _describe(secret_id)
        rotation_enabled = bool(desc.get("RotationEnabled"))
        logger.info("Secret %s rotation_enabled=%s", secret_id, rotation_enabled)

        if mode == "trigger" or (mode == "auto" and rotation_enabled):
            resp = _rotate_now(secret_id)
            return _ok({
                "action": "trigger_rotation",
                "secret_id": secret_id,
                "rotation_lambda": desc.get("RotationLambdaARN"),
                "rotation_started": True,
                "response": _redact(resp),
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

        # mode=set OR (mode=auto and rotation NOT enabled) → set a new value
        value_to_set = None
        if new_value is not None:
            # Accept either dict or string
            value_to_set = new_value if isinstance(new_value, str) else json.dumps(new_value)
        elif generate_random or mode in ("auto", "set"):
            value_to_set = _gen_password(
                length=random_length,
                exclude_punctuation=exclude_punc,
                require_each_type=require_each_type
            )
        else:
            return _err("No new_value provided and generate_random is false; nothing to rotate.")

        resp = _put_value(secret_id, value_to_set)
        return _ok({
            "action": "set_value",
            "secret_id": secret_id,
            "new_version_id": resp.get("VersionId"),
            "awscurrent_applied": "AWSCURRENT" in (resp.get("VersionStages") or []),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    except ClientError as e:
        logger.exception("AWS ClientError")
        return _err(f"AWS error: {e.response.get('Error', {}).get('Message', str(e))}", 500)
    except Exception as e:
        logger.exception("Unhandled error")
        return _err(f"Unhandled error: {str(e)}", 500)

def _redact(obj):
    # Simple redactor for responses
    if isinstance(obj, dict):
        return {k: _redact(v) for k, v in obj.items() if k.lower() not in {"secretstring", "clientrequesttoken"}}
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    return obj
