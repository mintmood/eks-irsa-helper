# eks-irsa-helper

Small CLI to validate that an IAM role's trust policy matches an EKS cluster's OIDC issuer, `sts.amazonaws.com` audience, and Kubernetes `ServiceAccount` subject.

## Usage

```bash
pip install -r requirements.txt
python check_irsa.py --cluster prod-eks --role app-s3-reader --namespace payments --sa worker
```

Exits `0` when valid, `1` otherwise.
