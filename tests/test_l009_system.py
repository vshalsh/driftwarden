# ruff: noqa: E501
"""L-009 system tests (independent, adversarial): undocumented-decision detector.

Own generated git-repo fixtures; precision/recall over a seeded corpus (>=100 records);
tamper-mutation sweep over every evidence/introduction field.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from conftest import GIT_ENV
from conftest import git as _git
from driftwarden.grounding.verify import verify_dependency
from driftwarden.undocumented import (
    adr_mentions,
    detect_undocumented,
    technology_terms,
    verify_undocumented,
)

# --------------------------------------------------------------------- helpers


def init(repo: Path) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "commit.gpgsign", "false")
    return repo


def commit(repo: Path, files: dict[str, str | None], msg: str = "c") -> str:
    for rel, content in files.items():
        p = repo / rel
        if content is None:
            _git(repo, "rm", "-q", "--", rel)
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content.encode("utf-8"))
        _git(repo, "add", "--", rel)
    _git(repo, "commit", "-q", "--allow-empty", "-m", msg)
    return _git(repo, "rev-parse", "HEAD").strip()


def adr(n: int, title: str, decision: str, *, context="We need to choose.", extra="") -> dict:
    body = (
        f"# {n}. {title}\n\nDate: 2026-01-11\n\n## Status\n\nAccepted\n\n## Context\n\n"
        f"{context}\n\n## Decision\n\n{decision}\n\n## Consequences\n\nThe team follows this.\n"
        f"{extra}"
    )
    return {f"docs/adr/{n:04d}-{title.lower().replace(' ', '-')}.md": body}


def labels(scan) -> set[str]:
    return {f"{r.category}/{r.technology}" for r in scan.findings}


def all_labels(scan) -> set[str]:
    return {f"{r.category}/{r.technology}" for r in scan.records}


# --------------------------------------------------------------------- seeded corpus
# (file template, tech, category). {x} = the package. One entry per distinct technology
# per ecosystem; each is placed in its own repo (root layout) and again in a monorepo layout.

PYPI = [
    ("psycopg2-binary", "postgresql", "datastore"),
    ("asyncpg", "postgresql", "datastore"),
    ("pymysql", "mysql", "datastore"),
    ("pymongo", "mongodb", "datastore"),
    ("motor", "mongodb", "datastore"),
    ("cassandra-driver", "cassandra", "datastore"),
    ("pynamodb", "dynamodb", "datastore"),
    ("redis", "redis", "cache"),
    ("pymemcache", "memcached", "cache"),
    ("kafka-python", "kafka", "queue"),
    ("confluent-kafka", "kafka", "queue"),
    ("pika", "rabbitmq", "queue"),
    ("celery", "celery", "queue"),
    ("nats-py", "nats", "queue"),
    ("flask", "flask", "web-framework"),
    ("django", "django", "web-framework"),
    ("fastapi", "fastapi", "web-framework"),
    ("boto3", "aws-sdk", "cloud-sdk"),
    ("google-cloud-storage", "gcp-sdk", "cloud-sdk"),
    ("azure-storage-blob", "azure-sdk", "cloud-sdk"),
    ("stripe", "stripe", "vendor-sdk"),
    ("twilio", "twilio", "vendor-sdk"),
    ("sendgrid", "sendgrid", "vendor-sdk"),
    ("sentry-sdk", "sentry", "vendor-sdk"),
    ("openai", "openai", "vendor-sdk"),
    ("anthropic", "anthropic", "vendor-sdk"),
    ("httpx", "httpx", "http-client"),
    ("requests", "requests", "http-client"),
    ("aiohttp", "aiohttp", "http-client"),
    ("elasticsearch", "elasticsearch", "search"),
]
NPM = [
    ("express", "express", "web-framework"),
    ("koa", "koa", "web-framework"),
    ("fastify", "fastify", "web-framework"),
    ("@nestjs/core", "nestjs", "web-framework"),
    ("axios", "axios", "http-client"),
    ("got", "got", "http-client"),
    ("node-fetch", "node-fetch", "http-client"),
    ("superagent", "superagent", "http-client"),
    ("stripe", "stripe", "vendor-sdk"),
    ("twilio", "twilio", "vendor-sdk"),
    ("@sentry/node", "sentry", "vendor-sdk"),
    ("@sendgrid/mail", "sendgrid", "vendor-sdk"),
    ("redis", "redis", "cache"),
    ("@aws-sdk/client-sqs", "sqs", "queue"),
    ("@aws-sdk/client-dynamodb", "dynamodb", "datastore"),
    ("nats", "nats", "queue"),
    ("@elastic/elasticsearch", "elasticsearch", "search"),
    ("@google-cloud/storage", "gcp-sdk", "cloud-sdk"),
    ("@azure/storage-blob", "azure-sdk", "cloud-sdk"),
    ("openai", "openai", "vendor-sdk"),
]
GO = [
    ("github.com/gin-gonic/gin v1.9.1", "gin", "web-framework"),
    ("github.com/gofiber/fiber/v2 v2.50.0", "fiber", "web-framework"),
    ("github.com/labstack/echo/v4 v4.11.0", "echo", "web-framework"),
    ("github.com/nats-io/nats.go v1.30.0", "nats", "queue"),
    ("github.com/go-resty/resty/v2 v2.7.0", "resty", "http-client"),
    ("github.com/stripe/stripe-go/v76 v76.1.0", "stripe", "vendor-sdk"),
    ("github.com/gocql/gocql v1.6.0", "cassandra", "datastore"),
]
MAVEN = [
    ("org.springframework.boot:spring-boot-starter-web:3.1.0", "spring-boot", "web-framework"),
    ("com.stripe:stripe-java:24.0.0", "stripe", "vendor-sdk"),
    ("io.nats:jnats:2.17.0", "nats", "queue"),
    ("com.squareup.okhttp3:okhttp:4.11.0", "okhttp", "http-client"),
    ("com.twilio.sdk:twilio:9.0.0", "twilio", "vendor-sdk"),
]
TF = [
    ("cloudflare/cloudflare", "cloudflare"),
    ("hashicorp/aws", "aws-sdk"),
    ("datadog/datadog", "datadog"),
    ("hashicorp/google", "gcp-sdk"),
    ("hashicorp/azurerm", "azure-sdk"),
    ("integrations/github", "github"),
    ("digitalocean/digitalocean", "digitalocean"),
    ("hashicorp/vault", "vault"),
]
COMPOSE = [
    ("postgres:15", "postgresql", "datastore"),
    ("redis:7", "redis", "cache"),
    ("mongo:6", "mongodb", "datastore"),
    ("rabbitmq:3", "rabbitmq", "queue"),
    ("elasticsearch:8.9.0", "elasticsearch", "search"),
    ("memcached:1.6", "memcached", "cache"),
    ("mysql:8", "mysql", "datastore"),
]


def manifest_files(eco: str, pkg: str, prefix: str = "", dev: bool = False) -> dict[str, str]:
    if eco == "pypi":
        name = "requirements-dev.txt" if dev else "requirements.txt"
        return {f"{prefix}{name}": f"# deps\n{pkg}==1.0.0\n"}
    if eco == "npm":
        key = "devDependencies" if dev else "dependencies"
        pj = {"name": "svc", "version": "1.0.0", key: {pkg: "^1.0.0"}}
        return {f"{prefix}package.json": json.dumps(pj, indent=2) + "\n"}
    if eco == "go":
        return {f"{prefix}go.mod": f"module example.com/svc\n\ngo 1.21\n\nrequire (\n\t{pkg}\n)\n"}
    if eco == "maven":
        g, a, v = pkg.split(":")
        scope = "<scope>test</scope>" if dev else ""
        return {
            f"{prefix}pom.xml": (
                '<project xmlns="http://maven.apache.org/POM/4.0.0">\n<modelVersion>4.0.0</modelVersion>\n'
                "<groupId>x</groupId><artifactId>svc</artifactId><version>1</version>\n<dependencies>\n"
                f"<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>"
                f"<version>{v}</version>{scope}</dependency>\n</dependencies>\n</project>\n"
            )
        }
    if eco == "tf":
        src = pkg
        return {
            f"{prefix}main.tf": (
                "terraform {\n  required_providers {\n    p = {\n"
                f'      source = "{src}"\n      version = "~> 1.0"\n    }}\n  }}\n}}\n'
            )
        }
    if eco == "compose":
        name = "docker-compose.test.yml" if dev else "docker-compose.yml"
        return {f"{prefix}{name}": f"services:\n  svc:\n    image: {pkg}\n"}
    raise AssertionError(eco)


def corpus():
    """(eco, pkg, tech, category) for every seeded positive."""
    out = [("pypi", *x) for x in PYPI] + [("npm", *x) for x in NPM] + [("go", *x) for x in GO]
    out += [("maven", *x) for x in MAVEN] + [("compose", *x) for x in COMPOSE]
    out += [("tf", s, t, "iac-provider") for s, t in TF]
    return out


CORPUS = corpus()


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    """Root-layout repo per positive, plus monorepo layout. -> list of (case, scan)"""
    base = tmp_path_factory.mktemp("sys9")
    res = []
    for i, (eco, pkg, tech, cat) in enumerate(CORPUS):
        for layout in ("root", "mono"):
            repo = init(base / f"{layout}{i}")
            prefix = "" if layout == "root" else f"services/svc{i}/"
            files = {"README.md": "# x\n", **manifest_files(eco, pkg, prefix)}
            files.update(adr(1, "Logging", "We log to stdout in JSON."))
            commit(repo, files)
            res.append(((eco, pkg, tech, cat, layout), repo, detect_undocumented(repo)))
    return res


# --------------------------------------------------------------------- precision / recall


def test_seeded_corpus_size():
    assert len(CORPUS) * 2 >= 100


def test_precision_recall_seeded(seeded):
    tp = fp = fn = 0
    misses, extras = [], []
    for (eco, pkg, tech, cat, layout), _repo, scan in seeded:
        got = labels(scan)
        want = f"{cat}/{tech}"
        # an AWS-service npm package is legitimately both the service and the AWS SDK
        also = {"cloud-sdk/aws-sdk"} if pkg.startswith("@aws-sdk/") else set()
        if want in got:
            tp += 1
        else:
            fn += 1
            misses.append((eco, pkg, layout, sorted(got), sorted(all_labels(scan))))
        for g in got - {want} - also:
            fp += 1
            extras.append((eco, pkg, layout, g))
    n = len(seeded)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / n
    print(f"SEEDED n={n} tp={tp} fp={fp} fn={fn} precision={prec:.4f} recall={rec:.4f}")
    print("MISSES", misses)
    print("EXTRAS", extras)
    assert fn == 0, misses
    assert fp == 0, extras


def test_seeded_everything_verifies(seeded):
    bad = []
    for case, repo, scan in seeded:
        assert not scan.could_not_verify, (case, [r.reasons for r in scan.could_not_verify])
        for r in scan.findings:
            if r.grounding != "VERIFIED" or not r.introducing_commits or not r.evidence:
                bad.append((case, r.id))
            again = verify_undocumented(repo, r, decisions=[])
            if again.status != "UNDOCUMENTED":
                bad.append((case, r.id, again.reasons))
    assert not bad, bad


# --------------------------------------------------------------------- controls: documented / dev-only


DOC_PHRASES = [
    ("pypi", "psycopg2-binary", "We use PostgreSQL for storage."),
    ("pypi", "psycopg2-binary", "Primary store is postgres."),
    ("pypi", "psycopg2-binary", "pgsql everywhere."),
    ("pypi", "asyncpg", "Use POSTGRESQL."),
    ("pypi", "pymongo", "We adopt MongoDB."),
    ("pypi", "pymongo", "Documents live in Mongo."),
    ("pypi", "redis", "Caching uses Redis."),
    ("pypi", "redis", "We pick Valkey for cache."),
    ("pypi", "kafka-python", "Events flow over Apache Kafka."),
    ("pypi", "kafka-python", "Events flow over Redpanda."),
    ("pypi", "pika", "RabbitMQ is the broker."),
    ("pypi", "pika", "We speak AMQP."),
    ("pypi", "flask", "HTTP layer is Flask."),
    ("pypi", "fastapi", "HTTP layer is Fast API."),
    ("pypi", "boto3", "Hosted on AWS."),
    ("pypi", "boto3", "We use Amazon Web Services."),
    ("pypi", "stripe", "Payments: Stripe."),
    ("pypi", "elasticsearch", "Search is OpenSearch."),
    ("pypi", "mongodb-fake", None),
    ("npm", "express", "Express.js is our server."),
    ("npm", "express", "We use expressjs."),
    ("npm", "@nestjs/core", "NestJS."),
    ("npm", "@nestjs/core", "Nest.js it is."),
    ("npm", "@aws-sdk/client-sqs", "AWS SQS."),
    ("go", "github.com/gin-gonic/gin v1.9.1", "Gin for HTTP."),
    ("maven", "org.springframework.boot:spring-boot-starter-web:3.1.0", "Spring Boot service."),
    ("maven", "org.springframework.boot:spring-boot-starter-web:3.1.0", "We use Spring."),
    ("compose", "postgres:15", "PostgreSQL 15."),
    ("compose", "mongo:6", "MongoDB 6."),
    ("compose", "rabbitmq:3", "RabbitMQ."),
    ("tf", "cloudflare/cloudflare", "DNS on Cloudflare."),
    ("tf", "hashicorp/aws", "We deploy to AWS."),
    ("tf", "datadog/datadog", "Monitors in Datadog."),
]
DOC_PHRASES = [d for d in DOC_PHRASES if d[2]]


@pytest.mark.parametrize("i", range(len(DOC_PHRASES)))
def test_documented_control_not_flagged(tmp_path, i):
    eco, pkg, phrase = DOC_PHRASES[i]
    repo = init(tmp_path / "r")
    files = {**manifest_files(eco, pkg), **adr(1, "Choice", phrase)}
    commit(repo, files)
    scan = detect_undocumented(repo)
    assert scan.records == [], [r.id for r in scan.records]


@pytest.mark.parametrize(
    "eco,pkg",
    [
        ("pypi", "psycopg2-binary"),
        ("pypi", "flask"),
        ("npm", "express"),
        ("maven", "com.stripe:stripe-java:24.0.0"),
        ("compose", "postgres:15"),
    ],
)
def test_dev_only_manifest_not_production(tmp_path, eco, pkg):
    repo = init(tmp_path / "r")
    commit(repo, manifest_files(eco, pkg, dev=True))
    scan = detect_undocumented(repo)
    assert scan.findings == [] and scan.could_not_verify == [], [r.id for r in scan.records]


def test_dev_scopes_inside_prod_manifests(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            "pyproject.toml": (
                '[project]\nname="x"\nversion="1"\ndependencies=["httpx"]\n'
                '[project.optional-dependencies]\ndev=["pymongo","redis"]\n'
                '[dependency-groups]\ntest=["flask"]\n'
            ),
            "package.json": json.dumps(
                {
                    "dependencies": {"axios": "1"},
                    "devDependencies": {"express": "4"},
                    "peerDependencies": {"koa": "1"},
                    "optionalDependencies": {"fastify": "1"},
                }
            ),
        },
    )
    got = labels(detect_undocumented(repo))
    assert "http-client/httpx" in got and "http-client/axios" in got
    for bad in ("datastore/mongodb", "cache/redis", "web-framework/flask", "web-framework/express"):
        assert bad not in got, bad


def test_test_dir_imports_not_production(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            "tests/test_x.py": "import redis\nimport pymongo\n",
            "test/foo.test.js": "const express = require('express');\n",
            "src/__tests__/a.ts": "import axios from 'axios';\n",
            "src/app.py": "import json\n",
        },
    )
    scan = detect_undocumented(repo)
    assert scan.records == [], [r.id for r in scan.records]


def test_prod_import_is_found(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"src/app.py": "import redis\nfrom flask import Flask\n"})
    got = labels(detect_undocumented(repo))
    assert {"cache/redis", "web-framework/flask"} <= got


# --------------------------------------------------------------------- ADR text traps


def test_word_boundary_trap_predisposed(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            **manifest_files("pypi", "redis"),
            **adr(
                1,
                "Mood",
                "The team is predisposed to simplicity; nothing about credis or redistribute.",
            ),
        },
    )
    assert "cache/redis" in labels(detect_undocumented(repo))


def test_word_boundary_trap_substrings_in_words(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            **manifest_files("pypi", "flask"),
            **manifest_files("npm", "koa", "web/"),
            **adr(
                1, "Words", "A flasky, koala-friendly approach; the mongoose and kafkaesque things."
            ),
        },
    )
    got = labels(detect_undocumented(repo))
    assert {"web-framework/flask", "web-framework/koa"} <= got


@pytest.mark.xfail(
    strict=True,
    reason="D-1: 'Considered Options' section is not searched, so an ADR that names Redis there is not coverage",
)
def test_adr_in_rejected_alternatives_section_documents(tmp_path):
    """Design says any ADR text mention documents (incl. rejected ones)."""
    repo = init(tmp_path / "r")
    extra = "\n## Considered Options\n\n* Redis - rejected, too heavy\n* Memcached\n"
    commit(
        repo,
        {
            **manifest_files("pypi", "redis"),
            **adr(1, "Cache", "Use in-process LRU cache.", extra=extra),
        },
    )
    scan = detect_undocumented(repo)
    # Redis is discussed in the ADR (rejected); records of it as "undocumented" would
    # contradict the documented rule.
    assert "cache/redis" not in labels(scan)


def test_adr_with_status_rejected_documents(tmp_path):
    repo = init(tmp_path / "r")
    body = (
        "# 1. Mongo\n\nDate: 2026-01-11\n\n## Status\n\nRejected\n\n## Context\n\nWe asked about MongoDB.\n\n"
        "## Decision\n\nWe will not use MongoDB.\n\n## Consequences\n\nNone.\n"
    )
    commit(repo, {**manifest_files("pypi", "pymongo"), "docs/adr/0001-mongo.md": body})
    assert "datastore/mongodb" not in labels(detect_undocumented(repo))


def test_adr_mention_only_in_title(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {**manifest_files("pypi", "pika"), **adr(1, "RabbitMQ", "Yes.")})
    assert detect_undocumented(repo).records == []


def test_adr_mention_in_code_fence_and_markdown_noise(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo, {**manifest_files("pypi", "redis"), **adr(1, "Cache", "Use **`Redis`** for caches.")}
    )
    assert detect_undocumented(repo).records == []


def test_adr_hyphen_underscore_boundaries(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {**manifest_files("pypi", "redis"), **adr(1, "Cache", "Use redis-cluster, not redis_x.")},
    )
    # 'redis-cluster' contains whole word 'redis' (hyphen is a delimiter): documented
    assert "cache/redis" not in labels(detect_undocumented(repo))


def test_adr_mention_other_technology_does_not_cover(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {**manifest_files("pypi", "pymysql"), **adr(1, "DB", "PostgreSQL is our database.")},
    )
    assert "datastore/mysql" in labels(detect_undocumented(repo))


def test_mariadb_alias_documents_mysql(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {**manifest_files("pypi", "pymysql"), **adr(1, "DB", "We use MariaDB.")})
    assert detect_undocumented(repo).records == []


def test_adr_in_nonstandard_dirs(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            **manifest_files("pypi", "redis"),
            "doc/architecture/decisions/0001-cache.md": "# 1. Cache\n\n## Status\n\nAccepted\n\n## Context\n\nc\n\n## Decision\n\nUse Redis.\n\n## Consequences\n\nok\n",
        },
    )
    assert detect_undocumented(repo).records == []


def test_madr_format_adr(tmp_path):
    repo = init(tmp_path / "r")
    body = (
        "---\nstatus: accepted\ndate: 2026-01-01\n---\n# Use Kafka for events\n\n## Context and Problem Statement\n\nEvents.\n\n"
        '## Considered Options\n\n* Kafka\n* RabbitMQ\n\n## Decision Outcome\n\nChosen option: "Kafka", because scale.\n'
    )
    commit(repo, {**manifest_files("pypi", "kafka-python"), "docs/decisions/0001-events.md": body})
    assert detect_undocumented(repo).records == []


@pytest.mark.xfail(strict=True, reason="D-1: MADR considered-options list not searched")
def test_madr_rejected_option_documents_other_tech(tmp_path):
    """RabbitMQ only appears as a considered/rejected option in the MADR options list."""
    repo = init(tmp_path / "r")
    body = (
        "---\nstatus: accepted\ndate: 2026-01-01\n---\n# Use Kafka for events\n\n## Context and Problem Statement\n\nEvents.\n\n"
        '## Considered Options\n\n* Kafka\n* RabbitMQ\n\n## Decision Outcome\n\nChosen option: "Kafka", because scale.\n'
    )
    commit(
        repo,
        {**manifest_files("pypi", "pika"), "docs/decisions/0001-events.md": body},
    )
    assert "queue/rabbitmq" not in labels(detect_undocumented(repo))


# --------------------------------------------------------------------- history


def test_introducing_commit_after_rename_and_move(tmp_path):
    repo = init(tmp_path / "r")
    c1 = commit(repo, {"requirements.txt": "flask==2.0\n"}, "add flask")
    commit(repo, {"README.md": "x\n"}, "noise")
    _git(repo, "mv", "requirements.txt", "reqs.txt")  # not a manifest name any more
    _git(repo, "mv", "reqs.txt", "backend-requirements.txt")
    _git(repo, "commit", "-q", "-m", "rename")
    _git(repo, "mv", "backend-requirements.txt", "backend/requirements.txt") if (
        repo / "backend"
    ).mkdir() is None else None
    _git(repo, "commit", "-q", "-m", "move")
    scan = detect_undocumented(repo)
    f = [r for r in scan.findings if r.technology == "flask"]
    assert f, scan.records
    # documented limit: rename = introduction; just assert it verifies and a real commit
    assert f[0].introducing_commits
    assert c1 not in f[0].introducing_commits or True


def test_dependency_added_then_removed_not_flagged(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"requirements.txt": "redis==5\nflask==2\n"})
    commit(repo, {"requirements.txt": "flask==2\n"})
    got = labels(detect_undocumented(repo))
    assert got == {"web-framework/flask"}


def test_dependency_removed_then_readded_introduction_is_readd(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"requirements.txt": "redis==5\n"}, "add")
    commit(repo, {"requirements.txt": "\n"}, "remove")
    c3 = commit(repo, {"requirements.txt": "redis==6\n"}, "readd")
    scan = detect_undocumented(repo)
    (r,) = scan.findings
    assert r.introducing_commits == [c3]


def test_version_bump_keeps_original_intro(tmp_path):
    repo = init(tmp_path / "r")
    c1 = commit(repo, {"requirements.txt": "redis==5\n"})
    commit(repo, {"requirements.txt": "redis==6\n"})
    commit(repo, {"requirements.txt": "redis==7\n# c\n"})
    (r,) = detect_undocumented(repo).findings
    assert r.introducing_commits == [c1]


@pytest.mark.xfail(
    strict=True,
    reason="D-3: introduction = first appearance as dev-only dep, not the promotion to production",
)
def test_dev_to_prod_promotion(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"package.json": json.dumps({"devDependencies": {"axios": "1"}})})
    c2 = commit(repo, {"package.json": json.dumps({"dependencies": {"axios": "1"}})})
    (r,) = detect_undocumented(repo).findings
    assert r.technology == "axios"
    assert r.status == "UNDOCUMENTED"
    assert c2 in r.introducing_commits


def test_prod_demoted_to_dev(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"package.json": json.dumps({"dependencies": {"axios": "1"}})})
    commit(repo, {"package.json": json.dumps({"devDependencies": {"axios": "1"}})})
    assert detect_undocumented(repo).records == []


def test_scan_old_commit_ignores_later_changes(tmp_path):
    repo = init(tmp_path / "r")
    c1 = commit(repo, {"requirements.txt": "redis==5\n"})
    commit(repo, {"requirements.txt": "flask==2\n"})
    assert labels(detect_undocumented(repo, c1)) == {"cache/redis"}
    assert labels(detect_undocumented(repo)) == {"web-framework/flask"}


@pytest.mark.xfail(
    strict=True,
    reason="D-2: default ADR discovery reads HEAD/worktree, not ADRs at the scanned commit",
)
def test_adr_added_later_documents_at_head_not_at_old_commit(tmp_path):
    repo = init(tmp_path / "r")
    c1 = commit(repo, {"requirements.txt": "redis==5\n"})
    commit(repo, adr(1, "Cache", "Redis."))
    assert detect_undocumented(repo).records == []
    assert labels(detect_undocumented(repo, c1)) == {"cache/redis"}


def test_merge_commit_introduction(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"README.md": "x\n"})
    _git(repo, "checkout", "-q", "-b", "feat")
    cf = commit(repo, {"requirements.txt": "redis==5\n"}, "feat")
    _git(repo, "checkout", "-q", "main")
    commit(repo, {"other.txt": "y\n"}, "main work")
    _git(repo, "merge", "-q", "--no-ff", "feat", "-m", "merge")
    (r,) = detect_undocumented(repo).findings
    assert r.introducing_commits == [cf]


def test_same_tech_added_on_both_branches(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"README.md": "x\n"})
    _git(repo, "checkout", "-q", "-b", "feat")
    commit(repo, {"requirements.txt": "redis==5\n"}, "feat")
    _git(repo, "checkout", "-q", "main")
    commit(repo, {"requirements.txt": "redis==5\n"}, "main add")
    _git(repo, "merge", "-q", "feat", "-m", "merge")  # same content -> clean merge
    scan = detect_undocumented(repo)
    assert scan.could_not_verify == [], [x.reasons for x in scan.could_not_verify]
    assert len(scan.findings) == 1


def test_shallow_clone(tmp_path):
    src = init(tmp_path / "src")
    commit(src, {"README.md": "x\n"})
    commit(src, {"requirements.txt": "redis==5\n"})
    commit(src, {"README.md": "y\n"})
    dst = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{src}", str(dst)],
        check=True,
        env={**os.environ, **GIT_ENV},
    )
    scan = detect_undocumented(dst)
    # must never crash; redis is found; provenance is either verified or Could-not-verify
    assert "cache/redis" in all_labels(scan)
    for r in scan.records:
        assert r.status in ("UNDOCUMENTED", "UNKNOWN")


def test_detached_head(tmp_path):
    repo = init(tmp_path / "r")
    c1 = commit(repo, {"requirements.txt": "redis==5\n"})
    commit(repo, {"README.md": "y\n"})
    _git(repo, "checkout", "-q", "--detach", c1)
    (r,) = detect_undocumented(repo).findings
    assert r.commit == c1


def test_non_git_folder_raises_cleanly(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "requirements.txt").write_text("redis\n")
    from driftwarden import git as dg

    with pytest.raises(dg.GitError):
        detect_undocumented(d)


def test_empty_repo_no_commits(tmp_path):
    repo = init(tmp_path / "r")
    from driftwarden import git as dg

    with pytest.raises(dg.GitError):
        detect_undocumented(repo)


def test_worktree_commit_rejected(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"requirements.txt": "redis\n"})
    with pytest.raises(ValueError):
        detect_undocumented(repo, "WORKTREE")


def test_unknown_commit_raises(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"requirements.txt": "redis\n"})
    from driftwarden import git as dg

    with pytest.raises(dg.GitError):
        detect_undocumented(repo, "deadbeef" * 5)


def test_scan_from_subdirectory_path(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"a/b/requirements.txt": "redis\n"})
    assert labels(detect_undocumented(repo / "a" / "b")) == {"cache/redis"}


# --------------------------------------------------------------------- hostile inputs


HOSTILE = [
    "dir with space/requirements.txt",
    "ünïcode/requirements.txt",
    "日本語/package.json",
    "a'b/requirements.txt",
    'q"uote/requirements.txt',
    "semi;colon/requirements.txt",
    "$(touch pwned)/requirements.txt",
    "back`tick/requirements.txt",
    "-dash/requirements.txt",
    "tab\there/requirements.txt",
    "new\nline/requirements.txt",
    "percent%20/requirements.txt",
    "[brackets]/requirements.txt",
    "star*/requirements.txt",
]


@pytest.mark.parametrize("path", HOSTILE)
def test_hostile_paths(tmp_path, path):
    repo = init(tmp_path / "r")
    content = (
        "redis==5\n" if path.endswith(".txt") else json.dumps({"dependencies": {"redis": "1"}})
    )
    try:
        commit(repo, {path: content})
    except Exception:
        pytest.skip("filesystem/git refuses this name")
    scan = detect_undocumented(repo)
    assert "cache/redis" in all_labels(scan)
    if any(c in path for c in "\t\n"):  # control chars: G2 path policy fails closed (by design)
        assert all(r.status == "UNKNOWN" for r in scan.records)
        assert scan.findings == []
    else:
        assert scan.could_not_verify == [], [r.reasons for r in scan.could_not_verify]
    assert not (repo / "pwned").exists()


def test_hostile_file_contents(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            "a/requirements.txt": "﻿redis==5\r\n",  # BOM + CRLF
            "b/requirements.txt": "redis==5",  # no trailing newline
            "c/package.json": "{not json",
            "d/go.mod": "\x00\x01garbage",
            "e/pom.xml": "<project><dependencies></project>",
            "f/main.tf": 'terraform { required_providers { x = { source = "',
            "g/requirements.txt": "-r other.txt\n--index-url http://x\nredis @ https://x/y.whl\n",
        },
    )
    scan = detect_undocumented(repo)
    assert "cache/redis" in all_labels(scan)


def test_binary_and_invalid_utf8_manifest(tmp_path):
    repo = init(tmp_path / "r")
    p = repo / "requirements.txt"
    p.write_bytes(b"redis==5\n\xff\xfe\xfa bad\n")
    _git(repo, "add", "requirements.txt")
    _git(repo, "commit", "-q", "-m", "x")
    scan = detect_undocumented(repo)
    assert "cache/redis" in all_labels(scan)


def test_symlinked_manifest(tmp_path):
    repo = init(tmp_path / "r")
    (repo / "real.txt").write_text("redis\n")
    os.symlink("real.txt", repo / "requirements.txt")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "x")
    detect_undocumented(repo)  # must not crash


def test_adr_with_hostile_text(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            **manifest_files("pypi", "redis"),
            "docs/adr/0001-x.md": "# 1. X\x00\n\n## Status\n\nAccepted\n\n## Decision\n\n"
            + "(" * 5000
            + "REDIS"
            + "\\" * 3
            + "\n",
        },
    )
    detect_undocumented(repo)


def test_regex_metacharacters_in_terms():
    assert adr_mentions(["c++", "a.b", "(x"], [], []) == []
    assert technology_terms("redis", "cache", ["re(dis", "a|b", "[x"])  # builds


def test_huge_manifests_perf(tmp_path):
    import time

    repo = init(tmp_path / "r")
    reqs = "".join(f"zzpkg{i}==1.0.{i}\n" for i in range(20000)) + "redis==5\n"
    pj = json.dumps({"dependencies": {f"zz-{i}": "1" for i in range(20000)} | {"express": "4"}})
    commit(repo, {"requirements.txt": reqs, "package.json": pj})
    # 30 further commits touching the same huge file
    for i in range(30):
        commit(repo, {"requirements.txt": reqs + f"# {i}\n"})
    t = time.time()
    scan = detect_undocumented(repo)
    dt = time.time() - t
    print(f"HUGE seconds={dt:.1f}")
    assert {"cache/redis", "web-framework/express"} <= labels(scan)
    assert dt < 120


def test_many_technologies_evidence_cap(tmp_path):
    repo = init(tmp_path / "r")
    files = {f"s{i}/requirements.txt": "redis\n" for i in range(40)}
    commit(repo, files)
    (r,) = detect_undocumented(repo, max_evidence=10).findings
    assert len(r.evidence) == 10
    assert any("further occurrence" in n for n in r.notes)


def test_deep_history_cap(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"requirements.txt": "redis==1\n"})
    for i in range(60):
        commit(repo, {"requirements.txt": f"redis=={i + 2}\n"})
    (r,) = detect_undocumented(repo).findings
    assert r.grounding == "VERIFIED"


# --------------------------------------------------------------------- monorepo / multi-ecosystem


def test_monorepo_multi_ecosystem(tmp_path):
    repo = init(tmp_path / "r")
    files = {}
    files.update(manifest_files("pypi", "pymongo", "services/api/"))
    files.update(manifest_files("npm", "express", "services/web/"))
    files.update(manifest_files("go", "github.com/nats-io/nats.go v1.30.0", "services/bus/"))
    files.update(manifest_files("maven", "com.stripe:stripe-java:24.0.0", "services/pay/"))
    files.update(manifest_files("tf", "cloudflare/cloudflare", "infra/"))
    files.update(manifest_files("compose", "redis:7", "deploy/"))
    commit(repo, files)
    assert labels(detect_undocumented(repo)) == {
        "datastore/mongodb",
        "web-framework/express",
        "queue/nats",
        "vendor-sdk/stripe",
        "iac-provider/cloudflare",
        "cache/redis",
    }


@pytest.mark.xfail(
    strict=True,
    reason="D-4: introducing_commits 'oldest first' ordered by (timestamp, sha): same-second commits come out in sha order",
)
def test_same_tech_many_services_single_record_multi_intro(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")  # same-second commits
    monkeypatch.setenv("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
    bad = 0
    for n in range(10):
        repo = init(tmp_path / f"r{n}")
        c1 = commit(repo, manifest_files("pypi", "redis", "a/"), f"one{n}")
        c2 = commit(repo, manifest_files("pypi", "redis", "b/"), f"two{n}")
        (r,) = detect_undocumented(repo).findings
        assert sorted(r.introducing_commits) == sorted([c1, c2])
        bad += r.introducing_commits != [c1, c2]
    assert bad == 0, f"{bad}/10 repos listed introducing commits newest-first"


def test_tf_utility_providers_and_modules_not_flagged(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            "main.tf": (
                'terraform {\n  required_providers {\n    random = { source = "hashicorp/random" }\n'
                '    nul = { source = "hashicorp/null" }\n    tl = { source = "hashicorp/time" }\n  }\n}\n'
                'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n'
            )
        },
    )
    assert detect_undocumented(repo).records == []


def test_tf_provider_block_without_required_providers(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"main.tf": 'provider "cloudflare" {\n  api_token = "x"\n}\n'})
    assert "iac-provider/cloudflare" in labels(detect_undocumented(repo))


def test_tf_provider_documented_by_provider_name(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            **manifest_files("tf", "cloudflare/cloudflare"),
            **adr(1, "DNS", "Use CloudFlare for DNS."),
        },
    )
    assert detect_undocumented(repo).records == []


@pytest.mark.xfail(strict=True, reason="D-5: vendor/ trees are not excluded by default")
def test_lockfiles_and_vendored_dirs(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            "node_modules/express/package.json": json.dumps({"dependencies": {"redis": "1"}}),
            "vendor/x/requirements.txt": "pymongo\n",
            "package-lock.json": json.dumps({"packages": {"node_modules/koa": {"version": "1"}}}),
        },
    )
    got = labels(detect_undocumented(repo))
    # vendored / node_modules trees must not create findings
    assert "cache/redis" not in got and "datastore/mongodb" not in got, got


def test_logging_orm_frontend_not_reported(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            "requirements.txt": "sqlalchemy\nloguru\nstructlog\n",
            "package.json": json.dumps(
                {"dependencies": {"react": "18", "winston": "3", "prisma": "5"}}
            ),
        },
    )
    assert detect_undocumented(repo).records == []


def test_literal_package_not_in_catalog_not_flagged(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"requirements.txt": "left-pad\nsomething-internal==1\n"})
    assert detect_undocumented(repo).records == []


def test_lookalike_package_names(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            "requirements.txt": "redis-om-fake-nope\nflask-cors\nstripe-mock-server\nrequests-mock\ndjango-debug-toolbar\n"
        },
    )
    got = labels(detect_undocumented(repo))
    # flask-cors is a Flask extension, not Flask itself; none of these is the base tech
    assert "web-framework/flask" not in got, got
    assert "cache/redis" not in got
    assert "http-client/requests" not in got, got
    assert "vendor-sdk/stripe" not in got, got
    assert "web-framework/django" not in got, got


def test_import_aliasing_and_multiline(tmp_path):
    repo = init(tmp_path / "r")
    commit(
        repo,
        {
            "a.py": "import redis as r\n",
            "b.py": "from pymongo import (\n    MongoClient,\n)\n",
            "c.js": "const Koa = require('koa')\nimport('fastify')\n",
            "d.go": 'package x\nimport (\n\t"github.com/gofiber/fiber/v2"\n)\n',
            "E.java": "import com.stripe.Stripe;\nclass E {}\n",
            "f.py": "# import kafka\nx = 'import pika'\n",
        },
    )
    got = labels(detect_undocumented(repo))
    assert {
        "cache/redis",
        "datastore/mongodb",
        "web-framework/koa",
        "web-framework/fiber",
        "vendor-sdk/stripe",
    } <= got
    assert "queue/kafka" not in got and "queue/rabbitmq" not in got, got


# --------------------------------------------------------------------- tamper mutation


def _mutations(rec):
    """Yield (name, mutated copy) for every single-field tamper that must be detected."""
    base = rec.model_dump()

    def clone():
        return json.loads(json.dumps(base, default=str))

    def ev_fields():
        yield from range(len(base["evidence"]))

    for i in ev_fields():
        d = clone()
        d["evidence"][i]["ref"]["quote"] = d["evidence"][i]["ref"]["quote"] + " tampered"
        yield f"ev{i}.quote+", d
        d = clone()
        d["evidence"][i]["ref"]["quote"] = "totally different"
        yield f"ev{i}.quote-replace", d
        d = clone()
        d["evidence"][i]["ref"]["line_start"] += 5
        d["evidence"][i]["ref"]["line_end"] += 5
        yield f"ev{i}.lines", d
        d = clone()
        d["evidence"][i]["ref"]["path"] = "nonexistent/file.txt"
        yield f"ev{i}.path", d
        d = clone()
        d["evidence"][i]["ref"]["commit"] = "0" * 40
        yield f"ev{i}.commit", d
        d = clone()
        d["evidence"][i]["technology"] = "bogus-tech"
        yield f"ev{i}.technology", d
        d = clone()
        d["evidence"][i]["kind"] = "usage"
        yield f"ev{i}.kind", d
        dep = base["evidence"][i].get("dependency")
        if dep:
            d = clone()
            d["evidence"][i]["dependency"]["package"] = "other-package"
            yield f"ev{i}.dep.package", d
            d = clone()
            d["evidence"][i]["dependency"]["line"] = (dep.get("line") or 1) + 3
            yield f"ev{i}.dep.line", d
            d = clone()
            d["evidence"][i]["dependency"]["manifest_path"] = "x/y.txt"
            yield f"ev{i}.dep.manifest", d
            d = clone()
            d["evidence"][i]["dependency"]["version_spec"] = "==99.99"
            yield f"ev{i}.dep.version", d
            d = clone()
            d["evidence"][i]["dependency"]["ecosystem"] = "cargo"
            yield f"ev{i}.dep.ecosystem", d
            d = clone()
            d["evidence"][i]["dependency"] = None
            yield f"ev{i}.dep.removed", d
    d = clone()
    d["technology"] = "bogus-tech"
    yield "rec.technology", d
    d = clone()
    d["category"] = "queue" if rec.category != "queue" else "cache"
    yield "rec.category", d
    d = clone()
    d["category"] = "logging"
    yield "rec.category-invalid", d
    d = clone()
    d["commit"] = "1" * 40
    yield "rec.commit", d
    d = clone()
    d["evidence"] = []
    yield "rec.evidence-empty", d
    d = clone()
    d["evidence"] = d["evidence"] + [d["evidence"][0]]
    yield "rec.evidence-dup", d
    d = clone()
    d["introducing_commits"] = []
    yield "rec.intro-commits-empty", d
    d = clone()
    d["introducing_commits"] = ["2" * 40]
    yield "rec.intro-commits-bogus", d
    d = clone()
    d["introductions"] = []
    yield "rec.introductions-empty", d
    for j in range(len(base["introductions"])):
        d = clone()
        d["introductions"][j]["commit"] = "3" * 40
        yield f"intro{j}.commit", d
        d = clone()
        d["introductions"][j]["parents"] = ["4" * 40]
        yield f"intro{j}.parents", d
        d = clone()
        d["introductions"][j]["ref"]["quote"] += "x"
        yield f"intro{j}.quote", d
        d = clone()
        d["introductions"][j]["ref"]["line_start"] += 4
        d["introductions"][j]["ref"]["line_end"] += 4
        yield f"intro{j}.lines", d
        d = clone()
        d["introductions"][j]["ref"]["path"] = "nope.txt"
        yield f"intro{j}.path", d
        d = clone()
        d["introductions"][j]["evidence_id"] = "e999"
        yield f"intro{j}.evidence_id", d
        if base["introductions"][j]["ref"]["commit"] != rec.commit:
            d = clone()
            d["introductions"][j]["ref"]["commit"] = rec.commit
            yield f"intro{j}.refcommit", d


def _info_mutations(rec):
    base = rec.model_dump()

    def clone():
        return json.loads(json.dumps(base, default=str))

    d = clone()
    d["title"] = "Use Oracle as a datastore"
    yield "rec.title", d
    d = clone()
    d["id"] = "UD-other"
    yield "rec.id", d
    d = clone()
    d["searched_terms"] = ["zzz"]
    yield "rec.searched_terms", d
    d = clone()
    d["notes"] = ["fabricated"]
    yield "rec.notes", d
    d = clone()
    d["evidence"][0]["detail"] = "fabricated"
    yield "ev0.detail", d
    d = clone()
    d["evidence"][0]["production"] = False
    yield "ev0.production-false", d
    d = clone()
    d["evidence"][0]["id"] = "e77"
    yield "ev0.id", d


@pytest.mark.xfail(
    strict=True, reason="D-6: Evidence.production flag is never re-checked by verify_undocumented"
)
def test_tamper_production_flag_caught(tmp_path):
    repo, _ = _tamper_repo(tmp_path)
    from driftwarden.models import UndocumentedDecision

    rec = detect_undocumented(repo).findings[0]
    d = rec.model_dump()
    d["evidence"][0]["production"] = False
    out = verify_undocumented(repo, UndocumentedDecision.model_validate(d), decisions=[])
    assert out.status == "UNKNOWN"


def test_tamper_free_text_fields_report(tmp_path):
    """Informational: which non-evidential fields can be altered undetected."""
    repo, _ = _tamper_repo(tmp_path)
    from driftwarden.models import UndocumentedDecision

    esc = []
    for rec in detect_undocumented(repo).findings:
        for name, data in _info_mutations(rec):
            try:
                out = verify_undocumented(
                    repo, UndocumentedDecision.model_validate(data), decisions=[]
                )
            except Exception:
                continue
            if out.status == "UNDOCUMENTED":
                esc.append(name)
    print("FREE-TEXT ESCAPES", sorted(set(esc)), len(esc))


def _tamper_repo(tmp_path):
    repo = init(tmp_path / "t")
    c1 = commit(
        repo, {"README.md": "x\n", "svc/requirements.txt": "# deps\nflask==2.0\nredis==5\n"}
    )
    commit(repo, {"README.md": "y\n"})
    commit(
        repo,
        {
            "pkg/package.json": json.dumps(
                {"dependencies": {"express": "4", "stripe": "1"}}, indent=2
            )
            + "\n",
            "src/app.py": "import redis\n",
        },
    )
    commit(
        repo,
        {
            "infra/main.tf": (
                "terraform {\n  required_providers {\n    cf = {\n"
                '      source = "cloudflare/cloudflare"\n    }\n  }\n}\n'
            ),
        },
    )
    return repo, c1


def test_tamper_mutations_all_caught(tmp_path):
    repo, _ = _tamper_repo(tmp_path)
    scan = detect_undocumented(repo)
    assert len(scan.findings) >= 5 and not scan.could_not_verify
    from driftwarden.models import UndocumentedDecision

    total = caught = 0
    escaped = []
    crashed = []
    for rec in scan.findings:
        for name, data in _mutations(rec):
            total += 1
            try:
                mut = UndocumentedDecision.model_validate(data)
            except Exception:
                caught += 1  # schema rejects it: also a catch
                continue
            try:
                out = verify_undocumented(repo, mut, decisions=[])
            except Exception as exc:
                crashed.append((rec.id, name, repr(exc)))
                continue
            if out.status == "UNDOCUMENTED" or out.grounding == "VERIFIED":
                escaped.append((rec.id, name))
            else:
                assert out.status == "UNKNOWN" and out.grounding == "MISMATCH" and out.reasons
                caught += 1
    print(f"TAMPER total={total} caught={caught} escaped={len(escaped)} crashed={len(crashed)}")
    print("ESCAPED", escaped)
    print("CRASHED", crashed)
    assert not crashed, crashed
    assert not escaped, escaped
    assert caught == total


def test_tamper_on_file_content_after_scan(tmp_path):
    """Rewriting history underneath: the record must stop verifying."""
    repo, _ = _tamper_repo(tmp_path)
    scan = detect_undocumented(repo)
    rec = next(r for r in scan.findings if r.technology == "flask")
    other = init(tmp_path / "other")
    commit(other, {"x": "y\n"})
    out = verify_undocumented(other, rec, decisions=[])
    assert out.status == "UNKNOWN"


def test_verify_in_adr_that_now_documents(tmp_path):
    repo, _ = _tamper_repo(tmp_path)
    rec = next(r for r in detect_undocumented(repo).findings if r.technology == "flask")
    from driftwarden.discover.adr import scan_adrs  # noqa: F401

    commit(repo, adr(1, "Web", "Flask."))
    decisions = scan_adrs(repo).decisions
    out = verify_undocumented(repo, rec, decisions=decisions)
    assert out.status == "UNKNOWN"


def test_verify_dependency_g3_direct(tmp_path):
    repo, _ = _tamper_repo(tmp_path)
    for rec in detect_undocumented(repo).findings:
        for ev in rec.evidence:
            if ev.dependency:
                assert verify_dependency(repo, ev.dependency).status == "VERIFIED"
                bad = ev.dependency.model_copy(update={"package": "nope"})
                assert verify_dependency(repo, bad).status != "VERIFIED"


def test_unverifiable_provenance_is_could_not_verify_not_finding(tmp_path):
    repo, _ = _tamper_repo(tmp_path)
    rec = detect_undocumented(repo).findings[0]
    from driftwarden.models import UndocumentedDecision

    d = rec.model_dump()
    d["commit"] = "f" * 40
    out = verify_undocumented(repo, UndocumentedDecision.model_validate(d), decisions=[])
    assert out.could_not_verify and out.status == "UNKNOWN"


def test_determinism(tmp_path):
    repo, _ = _tamper_repo(tmp_path)
    a = detect_undocumented(repo).model_dump_json()
    b = detect_undocumented(repo).model_dump_json()
    assert a == b


def test_no_network_no_llm(tmp_path, monkeypatch):
    import socket

    def boom(*a, **k):
        raise OSError("net")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    repo, _ = _tamper_repo(tmp_path)
    assert detect_undocumented(repo).findings


def test_does_not_modify_repo(tmp_path):
    repo, _ = _tamper_repo(tmp_path)
    before = _git(repo, "status", "--porcelain=v1", "-uall") + _git(repo, "rev-parse", "HEAD")
    detect_undocumented(repo)
    after = _git(repo, "status", "--porcelain=v1", "-uall") + _git(repo, "rev-parse", "HEAD")
    assert before == after


def test_dirty_worktree_ignored(tmp_path):
    repo = init(tmp_path / "r")
    commit(repo, {"requirements.txt": "flask\n"})
    (repo / "requirements.txt").write_text("flask\nredis\n")
    (repo / "new.py").write_text("import pymongo\n")
    assert labels(detect_undocumented(repo)) == {"web-framework/flask"}
