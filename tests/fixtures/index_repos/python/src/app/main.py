"""Entry point. The text below is not an import:
import not_a_module
"""

import os
import sys as system
from . import utils
from .models import User
from .sub import helpers
from .. import outside
import requests
from app.core.db import connect
import app.core
from app.plugins import p1
import importlib

try:
    import ujson as json
except ImportError:
    import json

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import User as U


def run() -> None:
    plugin = importlib.import_module("app.plugins.p1")
    note = "from fake import thing"
    print(os, system, utils, User, helpers, requests, connect, app, p1, json, U, plugin, note)


from app import (
    utils as u2,
    models,
)
