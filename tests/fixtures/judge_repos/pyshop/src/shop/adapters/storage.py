import boto3


def bucket(name: str):
    return boto3.resource("s3").Bucket(name)
