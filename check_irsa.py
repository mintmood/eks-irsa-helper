#!/usr/bin/env python3
import argparse
import json
import boto3


def check_role(role_name: str, oidc_issuer: str, namespace: str, service_account: str) -> bool:
    iam = boto3.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    doc = role["AssumeRolePolicyDocument"]
    expected_sub = f"system:serviceaccount:{namespace}:{service_account}"
    issuer_host = oidc_issuer.replace("https://", "")

    for stmt in doc.get("Statement", []):
        principal = stmt.get("Principal", {}).get("Federated", "")
        if issuer_host not in principal:
            continue
        cond = stmt.get("Condition", {}).get("StringEquals", {})
        if cond.get(f"{issuer_host}:sub") == expected_sub:
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


if __name__ == "__main__":
    main()
