import json
from shared import (
    UTC,
    get_session_for_account,
    is_exist_tag,
    send_notification,
)
import os
import yaml


def audit(resource, remediate=False, create_issues=False):
    is_compliant = True
    if resource["type"] != "security_group":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "security_group", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    ec2 = get_session_for_account(resource["account"], resource["region"], "ec2")
    security_group = ec2.describe_security_groups(GroupIds=[resource["id"]])
    security_group = security_group["SecurityGroups"][0]

    assigned_tags = []
    try:
        assigned_tags = security_group.get("Tags")
    except Exception as e:
        # If no tags exist, we get an exception that doesn't appear to be defined to catch, so we generically
        # catch the exception and look for the key phrase to indicate this problem, and if we can't find it,
        # we re-raise it
        if "NoSuchTagSet" not in str(e):
            raise e

    # Check if this allows ingress from 0.0.0.0/0 or the IPv6 equivalent ::/0
    allows_public_ingress = False
    for permission in security_group.get("IpPermissions", []):
        for ip_range in permission.get("IpRanges", []):
            if "/0" in ip_range.get("CidrIp", "") or "/0" in ip_range.get(
                "CidrIpv6", ""
            ):
                to_port = permission.get("ToPort", "")
                stream = open(os.environ['LAMBDA_TASK_ROOT'] + "/config/security.group.yml", 'r')
                data = yaml.safe_load(stream)
                tag_port_allow = data["security_group"]["port_allow"]
                port_allow_value = is_exist_tag(assigned_tags, tag_port_allow)
                if port_allow_value != "":
                    port_list = port_allow_value.split(",")
                    for port in port_list:
                        if to_port == int(port):
                            allows_public_ingress = False
                            print("Security Group allows public ingress to port {}: {}".format(
                              to_port, permission)
                            )
                            break
                        else:
                            allows_public_ingress = True

                    if allows_public_ingress:
                        is_compliant = False
                        issue = "Security Group {} not compliant - Allows public ingress to port {}".format(
                            resource["id"], to_port
                        )
                        if remediate:
                            if remediation_remove_inbound_rule(ec2, security_group.get("GroupId"), to_port):
                                issue += " - Remediated"
                                if remediation_create_tag(ec2, security_group.get("GroupId")):
                                    issue += " - Tagged"
                            else:
                                issue += " - Not remediated"
                        send_notification(issue, "", resource)

    return is_compliant


def remediation_remove_inbound_rule(ec2, sg_id, port):
    print("Remediating: Denying public ingress - {}".format(sg_id))
    ec2.revoke_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [
                    {
                        'CidrIp': '0.0.0.0/0'
                    },
                ]
            }
        ]
    )
    return True


def remediation_create_tag(ec2, sg_id):
    print("Creating Tag: - {}".format(sg_id))
    ec2.create_tags(
        Resources=[sg_id],
        Tags=[
            {
                'Key': 'Remediation Framework',
                'Value': 'True'
            }
        ]
    )
    return True
