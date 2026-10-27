import sqlite3

import requests


def test_smoke():
    assert sqlite3 and requests
