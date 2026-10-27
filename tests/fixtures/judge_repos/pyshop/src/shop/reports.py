"""Monthly reports."""

import csv

import boto3  # TODO: move behind the storage adapter


def upload(path: str) -> None:
    boto3.client("s3").upload_file(path, "reports", path)
