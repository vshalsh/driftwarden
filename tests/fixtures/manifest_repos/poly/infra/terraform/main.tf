terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    random = {
      source = "hashicorp/random"
    }
    google = "~> 4.0" # legacy shorthand
  }
}

/* A block comment with "quotes" and { braces } */
provider "aws" {
  region = var.region
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.7.0"

  name = "main-${var.env}"
  cidr = "10.0.0.0/16"
  tags = {
    Owner = "platform"
  }
}

module "local_thing" {
  source = "./modules/thing"
}

resource "aws_s3_bucket" "logs" {
  bucket = "logs-${var.env}"
  policy = <<EOF
{ "Version": "2012-10-17", "Statement": [] }
EOF
}
