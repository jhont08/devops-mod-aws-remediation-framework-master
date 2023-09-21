import json
import os
import yaml
from shared import (
    get_session_for_account,
    send_notification,
    is_missing_tags,
    is_exist_tag,
    get_required_tags,
)
from jira_wrapper import awsRemediationJira
from policyuniverse.policy import Policy


def audit(resource, remediate=False, create_issues=False):
    is_compliant = True
    jira = awsRemediationJira()
    if resource["type"] != "s3_bucket":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "s3_bucket", resource["type"]
            )
        )

    buckets_to_ignore = os.environ.get("S3_BUCKET_IGNORE_LIST", "")
    if resource["id"] in buckets_to_ignore.split(","):
        return True

    # Get a session in the account where this resource is
    s3 = get_session_for_account(resource["account"], resource["region"], "s3")

    # Ensure required tags exist
    assigned_tags = []
    try:
        assigned_tags = s3.get_bucket_tagging(Bucket=resource["id"])["TagSet"]
    except Exception as e:
        # If no tags exist, we get an exception that doesn't appear to be defined to catch, so we generically
        # catch the exception and look for the key phrase to indicate this problem, and if we can't find it,
        # we re-raise it
        if "NoSuchTagSet" not in str(e):
            raise e

    tags = get_required_tags()
    if not tags:
        if is_missing_tags(assigned_tags):
            is_compliant = False
            issue = "S3 bucket {} not compliant - Missing required tags - Not remediated".format(
                resource["id"]
            )
            if remediation_create_tag(s3, resource["id"]):
                issue += " - Tagged"
            else:
                issue += " - Not remediated"
            send_notification(issue, "Required tags: {}".format(", ".join(tags)), resource)

    stream = open(os.environ['LAMBDA_TASK_ROOT'] + "/config/s3.yml", 'r')
    data = yaml.safe_load(stream)
    tag_public = data["s3"]["tags"]["public"]
    tag_public_access_block = data["s3"]["tags"]["public_access_block"]
    tag_public_acl = data["s3"]["tags"]["public_acl"]
    tag_encrypted = data["s3"]["tags"]["encrypted"]
    tag_tls = data["s3"]["tags"]["tls"]

    public_value = is_exist_tag(assigned_tags, tag_public)
    if public_value != "True":
        policy_is_public = False
        try:
            status = s3.get_bucket_policy_status(Bucket=resource["id"])
            policy_is_public = status["PolicyStatus"]["IsPublic"]
        except Exception as e:
            print(e)
            print("No bucket policy: {}".format(resource["id"]))

        if policy_is_public:
            is_compliant = False
            issue = "S3 bucket policy {} is public".format(resource["id"])
            if remediate:
                if remediation_delete_bucket_policy(s3, resource):
                    issue += " - Remediated"
                    if remediation_create_tag(s3, resource["id"]):
                        issue += " - Tagged"
                else:
                    issue += " - Not remediated"
            send_notification(issue, "", resource)

    public_access_block_value = is_exist_tag(assigned_tags, tag_public_access_block)
    if public_access_block_value != "True":
        bucket_is_public = False
        try:
            bucket_is_public = public_allow(s3, resource)
        except Exception as e:
            print(e)
            print("Error bucket block public access: {}".format(resource["id"]))

        if bucket_is_public:
            is_compliant = False
            issue = "S3 bucket access block {} is public".format(resource["id"])
            if remediate:
                if remediation_block_public_access(s3, resource):
                    issue += " - Remediated"
                    if remediation_create_tag(s3, resource["id"]):
                        issue += " - Tagged"
                else:
                    issue += " - Not remediated"
            send_notification(issue, "", resource)

    public_acl_value = is_exist_tag(assigned_tags, tag_public_acl)
    if public_acl_value != "True":
        acl_is_public = False
        acl = s3.get_bucket_acl(Bucket=resource["id"])
        for i in range(len(acl["Grants"])):
            grantee_id = acl["Grants"][i]["Grantee"]
            if "http://acs.amazonaws.com/groups/global/AllUsers" in str(
                grantee_id
            ) or "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" in str(
                grantee_id
            ):
                acl_is_public = True
                break

        if acl_is_public:
            is_compliant = False
            issue = "S3 bucket ACL {} is public".format(resource["id"])
            if remediate:
                if remediation_make_acl_private(s3, resource):
                    issue += " - Remediated"
                    if remediation_create_tag(s3, resource["id"]):
                        issue += " - Tagged"
                else:
                    issue += " - Not remediated"
            send_notification(issue, "", resource)

    # Check the bucket policy for some things
    policy = None
    try:
        policy_string = s3.get_bucket_policy(Bucket=resource["id"])["Policy"]
        policy = json.loads(policy_string)
    except Exception as e:
        if "NoSuchBucketPolicy" in str(e):
            print("No bucket policy for {}".format(resource["id"]))
        else:
            print(e)
            raise e

    encrypted_value = is_exist_tag(assigned_tags, tag_encrypted)
    if encrypted_value != "True":
        if not denies_unencrypted_uploads(policy):
            is_compliant = False
            issue = "S3 bucket {} not compliant - Does not deny unencrypted uploads".format(
                resource["id"]
            )
            if create_issues:
                issue_jira = jira.create_issue(issue, resource)
                issue += " - Issue created {} ".format(issue_jira)

            # if remediate:
            #    if not remediation_make_policy_encrypted(s3, resource):
            #        issue += " - Not remediated"
            send_notification(issue, "", resource)

    tls_value = is_exist_tag(assigned_tags, tag_tls)
    if tls_value != "True":
        if not denies_lack_of_tls(policy):
            is_compliant = False
            issue = "S3 bucket {} not compliant - Does not deny non-TLS communications".format(
                resource["id"]
            )
            if create_issues:
                issue_jira = jira.create_issue(issue, resource)
                issue += " - Issue created {} ".format(issue_jira)
                print(issue)
            # if remediate:
            #    if not remediation_make_policy_unsecure_connection(s3, resource):
            #        issue += " - Not remediated"
            send_notification(issue, "", resource)

    if is_compliant:
        print("bucket is compliant: {}".format(resource["id"]))

    return is_compliant


def public_allow(s3, resource):
    response = s3.get_public_access_block(Bucket=resource["id"])
    if not response["PublicAccessBlockConfiguration"]["BlockPublicAcls"] or not response[
        "PublicAccessBlockConfiguration"]["IgnorePublicAcls"] or not response["PublicAccessBlockConfiguration"][
        "BlockPublicPolicy"] or not response["PublicAccessBlockConfiguration"]["RestrictPublicBuckets"]:
        return True
    return False


def denies_unencrypted_uploads(policy):
    if policy is None:
        return False

    # We want to ensure we have a statement that looks like:
    # {
    #     "Sid": "DenyUnencryptedObjectUploads",
    #     "Effect": "Deny",
    #     "Principal": "*",
    #     "Action": "s3:PutObject",
    #     "Resource": "arn:aws:s3:::my-bucket/*",
    #     "Condition": {
    #         "StringNotEquals": {
    #             "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
    #         }
    #     },
    # }

    statements = []
    statements.extend(policy["Statement"])
    for stmt in statements:
        if stmt["Effect"] != "Deny":
            continue
        if stmt.get("Principal", "") != "*":
            continue

        if (
            stmt.get("Action", "") == "*"
            or stmt.get("Action", "") == "s3:*"
            or stmt.get("Action", "") == "s3:PutObject"
        ):
            # The resource should be "arn:aws:s3:::my_bucket/*", "*", or "arn:aws:s3:::my_bucket*"
            # I'm cheating a bit and only checking if it has a "*"
            if "*" in stmt.get("Resource", ""):
                encryption_options = (
                    stmt.get("Condition", {})
                    .get("StringNotEquals", {})
                    .get("s3:x-amz-server-side-encryption", [])
                )
                if "aws:kms" in encryption_options:
                    return True
    return False


def denies_lack_of_tls(policy):
    if policy is None:
        return False

    # We want to ensure we have a statement that looks like:
    # {
    #     "Sid": "DenyUnsecureConnections",
    #     "Effect": "Deny",
    #     "Principal": "*",
    #     "Action": "s3:*",
    #     "Resource": "arn:aws:s3:::my_bucket/*",
    #     "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    # }

    statements = []
    statements.extend(policy["Statement"])
    for stmt in statements:
        if stmt["Effect"] != "Deny":
            continue
        if stmt.get("Principal", "") != "*":
            continue

        if stmt.get("Action", "") == "*" or stmt.get("Action", "") == "s3:*":
            # The resource should be "arn:aws:s3:::my_bucket/*", "*", or "arn:aws:s3:::my_bucket*"
            # I'm cheating a bit and only checking if it has a "*"
            if "*" in stmt.get("Resource", ""):
                if (
                    stmt.get("Condition", {})
                    .get("Bool", {})
                    .get("aws:SecureTransport", "")
                    == "false"
                ):
                    return True
    return False


def remediation_block_public_access(s3, resource):
    try:
        s3.put_public_access_block(
            PublicAccessBlockConfiguration={
              'BlockPublicAcls': True,
              'IgnorePublicAcls': True,
              'BlockPublicPolicy': True,
              'RestrictPublicBuckets': True
            },
            Bucket=resource["id"]
        )
    except Exception as e:
        print(e)
        return False
    return True


def generate_bucket_policy(bucket):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyUnsecureConnections",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::" + bucket + "/*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
            {
                "Sid": "DenyUnencryptedObjectUploads",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::" + bucket + "/*",
                "Condition": {
                    "StringNotEquals": {
                      "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
                    }
                },
            },
        ],
    }
    return policy


def remediation_delete_bucket_policy(s3, resource):
    try:
        s3.delete_bucket_policy(Bucket=resource["id"])
    except Exception as e:
        print(e)
        return False
    return True


def remediation_make_acl_private(s3, resource):
    try:
        s3.put_bucket_acl(Bucket=resource["id"], ACL="private")
    except Exception as e:
        print(e)
        return False
    return True


def remediation_make_policy_encrypted(s3, resource):
    try:
        policy = json.dumps(generate_bucket_policy(resource["id"]))
        s3.put_bucket_policy(Bucket=resource["id"], Policy=policy)
    except Exception as e:
        print(e)
        return False
    return True


def remediation_make_policy_unsecure_connection(s3, resource):
    try:
        policy = json.dumps(generate_bucket_policy(resource["id"]))
        s3.put_bucket_policy(Bucket=resource["id"], Policy=policy)
    except Exception as e:
        print(e)
        return False
    return True


def remediation_create_tag(s3, bucket_id):
    print("Creating Tag: - {}".format(bucket_id))
    s3.put_bucket_tagging(
        Bucket=bucket_id,
        Tagging={
            'TagSet': [
                {
                    'Key': 'Remediation Framework',
                    'Value': 'True'
                }
            ]
        }
    )
    return True
