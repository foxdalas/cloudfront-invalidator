# Cloudfront Invalidator

This GitHub Action invalidates the CloudFront cache for specified paths by finding the CloudFront distribution based on tags.

## Usage

Use this action to invalidate specific paths in a CloudFront distribution. The action finds the CloudFront distribution using tags and invalidates the provided paths.

```yaml
- uses: foxdalas/cloudfront-invalidator@v1
  with:
    # Cloudfont distribution tag key to identify the distribution
    tag_key: ""
    # Cloudfront distribution tag value to identify the distribution
    tag_value: ""
    # Paths to invalidate. Provide paths in a JSON array format, e.g., '["/path1", "/path2"]'. Paths must start with a '/'
    paths: '/index.html, /assets/*]'
    # Wait for the invalidation to complete. Default is true
    wait: true
```

### Example Workflow

```yaml
name: Invalidate CloudFront Cache

on:
  push:
    branches:
      - master

jobs:
  invalidate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Invalidate CloudFront paths
        uses: foxdalas/cloudfront-invalidator@v1
        with:
          tag_key: "Environment"
          tag_value: "Production"
          paths: "/index.html, /assets/*"
          wait: true
```
