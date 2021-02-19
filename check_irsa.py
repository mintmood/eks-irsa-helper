#!/usr/bin/env python3
import argparse
import fnmatch
import json
import sys
import boto3


def matches_condition(cond_block: dict, key: str, expected: str, allow_wildcard: bool) -> bool:
    val = cond_block.get(key)
    if val is None:
        return False
    values = val if isinstance(val, list) else [val]
    if allow_wildcard:
        return any(fnmatch.fnmatch(expected, pattern) for pattern in values)
    return expected in values


def check_role(role_name: str, oidc_issuer: str, namespace: str, service_account: str) -> bool:
    iam = boto3.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    doc = role["AssumeRolePolicyDocument"]
    expected_sub = f"system:serviceaccount:{namespace}:{service_account}"
    issuer_host = oidc_issuer.replace("https://", "")

    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {}).get("Federated", "")
        if issuer_host not in principal:
            continue
        cond = stmt.get("Condition", {})
        eq = cond.get("StringEquals", {})
        like = cond.get("StringLike", {})
        sub_ok = (
            matches_condition(eq, f"{issuer_host}:sub", expected_sub, False)
            or matches_condition(like, f"{issuer_host}:sub", expected_sub, True)
        )
        aud_ok = matches_condition(eq, f"{issuer_host}:aud", "sts.amazonaws.com", False)
        if sub_ok and aud_ok:
            return True
    return False


def main():
    p = argparse.ArgumentParser(description="Verify EKS IRSA trust policy for a ServiceAccount")
    p.add_argument("--cluster", required=True)
    p.add_argument("--role", required=True)
    p.add_argument("--namespace", default="default")
    p.add_argument("--sa", required=True)
    args = p.parse_args()

    eks = boto3.client("eks")
    issuer = eks.describe_cluster(name=args.cluster)["cluster"]["identity"]["oidc"]["issuer"]
    ok = check_role(args.role, issuer, args.namespace, args.sa)
    print(json.dumps({"cluster": args.cluster, "role": args.role, "issuer": issuer, "valid": ok}))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
