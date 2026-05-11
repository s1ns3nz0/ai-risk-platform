# Sample Terraform configuration with intentional IaC vulnerabilities.
# This is a FIXTURE for demo/testing purposes only.

provider "aws" {
  region = "ap-northeast-1"
}

# Vulnerability: S3 bucket without encryption (CKV_AWS_19)
# Vulnerability: S3 bucket without versioning (CKV_AWS_21)
resource "aws_s3_bucket" "data" {
  bucket = "payment-data-bucket"
  acl    = "private"

  tags = {
    Name        = "payment-data"
    Environment = "production"
  }
}

# Vulnerability: Overly permissive IAM policy (CKV_AWS_1)
resource "aws_iam_policy" "admin" {
  name        = "admin-policy"
  description = "Admin access policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# Vulnerability: Security group with 0.0.0.0/0 ingress (CKV_AWS_24)
resource "aws_security_group" "public" {
  name        = "public-sg"
  description = "Public security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
