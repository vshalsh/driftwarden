"""Database access."""

import psycopg2


def connect(dsn: str):
    return psycopg2.connect(dsn)
