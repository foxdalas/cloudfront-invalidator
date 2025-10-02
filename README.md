# CloudFront Invalidator

[![GitHub Release](https://img.shields.io/github/v/release/foxdalas/cloudfront-invalidator)](https://github.com/foxdalas/cloudfront-invalidator/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A GitHub Action that automatically invalidates AWS CloudFront cache by finding distributions using AWS resource tags. Perfect for CI/CD pipelines to ensure your CloudFront distributions serve fresh content after deployments.

## Features

- 🏷️ **Tag-based Discovery** - Automatically finds CloudFront distributions using AWS tags
- 🔒 **OIDC Support** - Secure authentication with temporary credentials (recommended for production)
- 🔄 **Automatic Retry Logic** - Built-in retry mechanism with exponential backoff for AWS throttling
- 🎯 **Multi-Distribution Support** - Invalidates cache across multiple distributions matching the same tags
- ⏱️ **Configurable Wait** - Optionally wait for invalidation completion with custom timeout
- 🛡️ **Path Auto-formatting** - Automatically ensures paths start with `/`
- 📊 **Detailed Logging** - Comprehensive logging for monitoring and debugging

## Table of Contents

- [Prerequisites](#prerequisites)
- [Inputs](#inputs)
- [Usage](#usage)
  - [Basic Example](#basic-example)
  - [Using OIDC (Recommended)](#using-oidc-recommended)
  - [Advanced Examples](#advanced-examples)
- [AWS IAM Permissions](#aws-iam-permissions)
- [How It Works](#how-it-works)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

1. **AWS Account** with CloudFront distributions
2. **AWS Authentication** - Choose one of the following methods:
   - **OIDC (Recommended)**: Configure OpenID Connect for secure, temporary credentials
   - **Static Credentials**: Store AWS Access Key ID and Secret Access Key in GitHub Secrets
   - See [AWS IAM Permissions](#aws-iam-permissions) for required permissions
3. **CloudFront Distribution Tags** - Your distributions must be tagged with identifiable key-value pairs

## Inputs

| Input       | Required | Default | Description                                                                                                            |
| ----------- | -------- | ------- | ---------------------------------------------------------------------------------------------------------------------- |
| `tag_key`   | Yes      | -       | AWS tag key to identify the CloudFront distribution(s)                                                                 |
| `tag_value` | Yes      | -       | AWS tag value to identify the CloudFront distribution(s)                                                               |
| `paths`     | Yes      | -       | Comma-separated paths to invalidate (e.g., `/index.html, /assets/*`). Paths automatically prefixed with `/` if missing |
| `wait`      | No       | `true`  | Wait for the invalidation to complete before proceeding                                                                |
| `timeout`   | No       | `600`   | Maximum wait time in seconds when `wait` is `true`                                                                     |

## Usage

### Basic Example

```yaml
name: Deploy and Invalidate Cache

on:
  push:
    branches:
      - main

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Invalidate CloudFront cache
        uses: foxdalas/cloudfront-invalidator@v4
        with:
          tag_key: "Environment"
          tag_value: "Production"
          paths: "/index.html, /assets/*"
```

### Using OIDC (Recommended)

OIDC provides secure, temporary credentials without storing long-term AWS access keys. This is the **recommended approach** for production environments.

#### Prerequisites for OIDC

1. Create an OIDC Identity Provider in AWS IAM
2. Create an IAM Role with trust policy for GitHub Actions
3. Attach necessary permissions to the role

#### Basic OIDC Example

```yaml
name: Deploy with OIDC

on:
  push:
    branches:
      - main

permissions:
  id-token: write # Required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials using OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1

      - name: Invalidate CloudFront cache
        uses: foxdalas/cloudfront-invalidator@v4
        with:
          tag_key: "Environment"
          tag_value: "Production"
          paths: "/index.html, /assets/*"
```

#### OIDC with GitHub Environments

Use GitHub Environments for better separation and security:

```yaml
name: Deploy to Production

on:
  push:
    branches:
      - main

permissions:
  id-token: write
  contents: read

jobs:
  invalidate:
    runs-on: ubuntu-latest
    environment: production # GitHub Environment with protection rules
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.AWS_ROLE_ARN }} # Environment variable
          aws-region: us-east-1

      - name: Invalidate CloudFront
        uses: foxdalas/cloudfront-invalidator@v4
        with:
          tag_key: "Environment"
          tag_value: "production"
          paths: "/*"
```

#### AWS OIDC Setup Guide

<details>
<summary>Click to expand AWS OIDC configuration steps</summary>

##### 1. Create OIDC Identity Provider

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

##### 2. Create IAM Role Trust Policy

Create a file `trust-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:*"
        }
      }
    }
  ]
}
```

##### 3. Create IAM Role

```bash
aws iam create-role \
  --role-name GitHubActionsRole \
  --assume-role-policy-document file://trust-policy.json
```

##### 4. Attach Permissions Policy

```bash
aws iam put-role-policy \
  --role-name GitHubActionsRole \
  --policy-name CloudFrontInvalidationPolicy \
  --policy-document file://permissions-policy.json
```

Where `permissions-policy.json` contains the permissions from the [AWS IAM Permissions](#aws-iam-permissions) section.

##### 5. More Restrictive Trust Policy (Branch-specific)

For better security, restrict OIDC access to specific branches:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

</details>

#### OIDC with Multiple Distributions

Invalidate multiple distributions with different tags in parallel:

```yaml
name: Invalidate Multiple Distributions

on:
  push:
    branches:
      - main

permissions:
  id-token: write
  contents: read

jobs:
  invalidate:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - tag_value: "api-production"
            paths: "/v1/*, /v2/*"
          - tag_value: "web-production"
            paths: "/index.html, /assets/*"
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1

      - name: Invalidate CloudFront
        uses: foxdalas/cloudfront-invalidator@v4
        with:
          tag_key: "Project"
          tag_value: ${{ matrix.tag_value }}
          paths: ${{ matrix.paths }}
```

### Advanced Examples

#### Invalidate Multiple Specific Paths

```yaml
- name: Invalidate specific paths
  uses: foxdalas/cloudfront-invalidator@v4
  with:
    tag_key: "Project"
    tag_value: "MyWebsite"
    paths: "/index.html, /about.html, /css/*, /js/*, /images/*"
    wait: true
    timeout: 900
```

#### Invalidate Everything (Use with Caution)

```yaml
- name: Invalidate all cache
  uses: foxdalas/cloudfront-invalidator@v4
  with:
    tag_key: "Environment"
    tag_value: "Staging"
    paths: "/*"
    wait: false
```

#### Multi-Environment Deployment

```yaml
name: Multi-Environment Cache Invalidation

on:
  workflow_dispatch:
    inputs:
      environment:
        description: "Environment to invalidate"
        required: true
        type: choice
        options:
          - staging
          - production

jobs:
  invalidate:
    runs-on: ubuntu-latest
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Invalidate CloudFront
        uses: foxdalas/cloudfront-invalidator@v4
        with:
          tag_key: "Environment"
          tag_value: ${{ github.event.inputs.environment }}
          paths: "/index.html, /assets/*"
```

## AWS IAM Permissions

The AWS credentials used must have the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"],
      "Resource": "arn:aws:cloudfront::<account-id>:distribution/*"
    },
    {
      "Effect": "Allow",
      "Action": ["tag:GetResources"],
      "Resource": "*"
    }
  ]
}
```

### Minimal IAM Policy Example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudFrontInvalidation",
      "Effect": "Allow",
      "Action": ["cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"],
      "Resource": "*"
    },
    {
      "Sid": "ResourceGroupsTagging",
      "Effect": "Allow",
      "Action": "tag:GetResources",
      "Resource": "*"
    }
  ]
}
```

## How It Works

1. **Discovery Phase**: The action queries AWS Resource Groups Tagging API to find CloudFront distribution(s) matching the specified tags
2. **Path Formatting**: Ensures all paths start with `/` for proper invalidation
3. **Invalidation Creation**: Creates invalidation requests for each discovered distribution
4. **Retry Logic**: Automatically retries on throttling errors (up to 12 attempts with exponential backoff)
5. **Wait (Optional)**: Monitors invalidation status until completion if `wait: true`

## Troubleshooting

### No distributions found

**Error**: `No ARN found with the provided tags`

**Solution**:

- Verify your CloudFront distribution has the correct tags
- Ensure `tag_key` and `tag_value` exactly match the distribution tags (case-sensitive)
- Check that AWS credentials have `tag:GetResources` permission

### Throttling errors

**Error**: Throttling detected during invalidation

**Solution**:

- The action automatically retries with exponential backoff
- Consider spacing out invalidations if running multiple workflows
- AWS CloudFront has rate limits on invalidation requests

### Permission denied

**Error**: Access denied when creating invalidation

**Solution**:

- Verify IAM permissions include `cloudfront:CreateInvalidation`
- Ensure the distribution ARN is included in the IAM policy resource
- Check that AWS credentials are correctly configured

### Timeout waiting for completion

**Error**: Invalidation timeout

**Solution**:

- Increase the `timeout` value (default is 600 seconds)
- Consider setting `wait: false` if you don't need to wait for completion
- Note: CloudFront invalidations typically complete in 10-15 minutes

### OIDC Authentication Errors

**Error**: `Unable to assume role` or `Not authorized to perform sts:AssumeRoleWithWebIdentity`

**Solution**:

- Verify OIDC provider is configured in AWS IAM
- Ensure IAM role trust policy allows GitHub Actions
- Check that `permissions: id-token: write` is set in workflow
- Verify the role ARN is correct
- Confirm the repository name in trust policy matches exactly (case-sensitive)

**Error**: `Token is expired` or `Invalid identity token`

**Solution**:

- Ensure GitHub Actions workflow has `id-token: write` permission
- Verify OIDC provider thumbprint is correct: `6938fd4d98bab03faadb97b34396831e3780aea1`
- Check that the token audience (`aud`) is set to `sts.amazonaws.com`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development

```bash
# Install dependencies
npm install

# Build the action
npm run build

# Format code
npm run fix:format
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Note**: This action uses AWS SDK v3 and requires Node.js 20+. CloudFront invalidations may take 10-15 minutes to complete and are subject to AWS service limits.
