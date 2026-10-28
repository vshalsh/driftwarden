"""Built-in technology catalog: what a claim term means in manifests and imports.

A claim says "PostgreSQL is the only datastore" or "No cloud SDK outside
adapters/". To check it deterministically, the judge must know which
dependencies and imports *are* PostgreSQL, and which other technologies are
datastores. This module is that table. It is deliberately small, generic and
easy to extend; it is not an attempt to list every package in every ecosystem.

**Technologies.** A :class:`Technology` has an ``id`` (``"mongodb"``), a
``category`` (``"datastore"``), ``aliases`` (the words an ADR uses for it:
``"mongo"``, ``"mongodb"``) and ``patterns``. A pattern is
``"<namespace>:<glob>"``; the glob is matched (``fnmatch``, case-insensitive) on:

============  ===============================================================
namespace     matched against
============  ===============================================================
``pypi``      PyPI distribution names (PEP 503-normalised on both sides)
``py``        Python import modules (the top-level name *and* the dotted path)
``npm``       npm package names, and JS/TS import package names
``maven``     Maven/Gradle coordinates ``group:artifact``
``java``      Java import names (``com.mongodb.client.MongoClient``)
``go``        Go module paths (go.mod) and Go import paths
``nuget``     NuGet package ids
``docker``    container images, by repository basename (``bitnami/redis`` -> ``redis``)
              and by full canonical name
``terraform`` Terraform provider / module sources
============  ===============================================================

**Categories.** :data:`CATEGORIES` maps a category id to the phrases an ADR uses
for it ("datastore", "database", "message broker", "cloud SDK", ...).
``only``-claims use it to find *other members* of the same category; boundary
claims use it when the restricted thing is a category ("cloud SDK").

**Extending.** Call :func:`register_technology` / :func:`register_category`
(e.g. from a plugin or a test), or add entries below. Ids must be unique; a
technology may name a category that is not in :data:`CATEGORIES` only if that
category is registered too.

**Literal fallback.** A term that is neither a technology alias nor a category
phrase, but looks like a package name (one token such as ``boto3``,
``requests``, ``@aws-sdk/client-s3``, ``org.mongodb:mongodb-driver-sync``), is
matched literally against every namespace (see :func:`literal_technology`).
Plain words, programming languages and protocols are never literal matches:
they yield no resolution, and the judge reports UNKNOWN rather than guess.

Terraform: providers are matched by source (``hashicorp/aws`` -> AWS, ``hashicorp/google``
-> GCP, ``hashicorp/azurerm`` -> Azure, ``mongodb/mongodbatlas``, ``confluentinc/confluent``,
``elastic/ec``, ...). Terraform *resources* (``aws_db_instance`` with
``engine = "postgres"``) are not parsed by the manifest layer, so a datastore created
only as a managed cloud resource is not seen.

Known limits: the catalog is name-based. It does not see a technology used
through a generic client (DynamoDB through ``boto3``), through a URL in config
(``mongodb://`` in an env file), or vendored source code.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- types

NAMESPACES = ("pypi", "py", "npm", "maven", "java", "go", "nuget", "docker", "terraform")


@dataclass(frozen=True)
class Technology:
    """One technology: how ADRs name it and how it shows up in code."""

    id: str
    category: str | None
    aliases: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()
    literal: bool = field(default=False, compare=False)
    """True for a pseudo-technology built from a literal package-like term."""

    def __post_init__(self) -> None:
        for p in self.patterns:
            ns, sep, glob = p.partition(":")
            if not sep or ns not in NAMESPACES or not glob:
                raise ValueError(f"{self.id}: bad pattern {p!r} (want '<namespace>:<glob>')")

    def globs(self, namespace: str) -> list[str]:
        pre = namespace + ":"
        return [p[len(pre) :] for p in self.patterns if p.startswith(pre)]


@dataclass(frozen=True)
class Resolution:
    """What a claim term resolved to."""

    term: str
    kind: str  # "technology" | "category" | "literal"
    technologies: tuple[Technology, ...]
    category: str | None = None

    @property
    def label(self) -> str:
        if self.kind == "category":
            return f"category {self.category}"
        return ", ".join(t.id for t in self.technologies)


# --------------------------------------------------------------------------- tables

CATEGORIES: dict[str, tuple[str, ...]] = {
    "datastore": (
        "datastore", "data store", "database", "db", "primary database", "relational database",
        "sql database", "document store", "document database", "nosql database",
        "persistence store", "storage backend", "primary datastore",
    ),
    "cache": ("cache", "caching", "cache layer", "cache store", "cache server", "in-memory cache"),
    "queue": (
        "queue", "message queue", "message broker", "broker", "messaging", "messaging system",
        "event bus", "event broker", "streaming platform", "pub/sub", "task queue", "job queue",
    ),
    "http-client": (
        "http client", "http library", "http client library", "http", "http requests",
        "rest client",
    ),
    "web-framework": (
        "web framework", "backend framework", "api framework", "http framework",
        "server framework", "web server framework",
    ),
    "frontend-framework": (
        "frontend framework", "front-end framework", "ui framework", "ui library",
        "frontend library", "front-end library", "spa framework",
    ),
    "orm": ("orm", "object relational mapper", "object-relational mapper"),
    "logging": ("logging", "logger", "logging library", "log library", "structured logging"),
    "cloud-sdk": (
        "cloud sdk", "cloud provider sdk", "cloud client", "cloud library", "cloud api client",
    ),
    "search": ("search engine", "search index", "full-text search engine"),
    "vendor-sdk": (
        "vendor sdk", "third-party sdk", "third party sdk", "saas sdk", "vendor api client",
    ),
}  # fmt: skip

_T = Technology

TECHNOLOGIES: list[Technology] = [
    # ---- datastores
    _T("postgresql", "datastore", ("postgresql", "postgres", "postgre sql", "pgsql"), (
        "pypi:psycopg2", "pypi:psycopg2-binary", "pypi:psycopg", "pypi:psycopg-binary",
        "pypi:asyncpg", "pypi:pg8000", "py:psycopg2", "py:psycopg", "py:asyncpg", "py:pg8000",
        "npm:pg", "npm:pg-promise", "npm:postgres", "maven:org.postgresql:*",
        "java:org.postgresql*", "go:github.com/lib/pq*", "go:github.com/jackc/pgx*",
        "nuget:npgsql*", "docker:postgres", "docker:postgresql",
        "terraform:*cyrilgdn/postgresql",
    )),
    _T("mysql", "datastore", ("mysql", "mariadb"), (
        "pypi:mysqlclient", "pypi:pymysql", "pypi:mysql-connector-python", "pypi:aiomysql",
        "py:mysqldb", "py:pymysql", "py:mysql.connector*", "py:aiomysql", "npm:mysql",
        "npm:mysql2", "npm:mariadb", "maven:mysql:mysql-connector-java", "maven:com.mysql:*",
        "maven:org.mariadb.jdbc:*", "java:com.mysql*", "go:github.com/go-sql-driver/mysql*",
        "nuget:mysql.data*", "nuget:mysqlconnector*", "docker:mysql", "docker:mariadb",
        "terraform:*petoju/mysql",
    )),
    _T("sqlite", "datastore", ("sqlite", "sqlite3"), (
        "py:sqlite3", "pypi:aiosqlite", "py:aiosqlite", "npm:sqlite3", "npm:better-sqlite3",
        "maven:org.xerial:sqlite-jdbc", "java:org.sqlite*", "go:github.com/mattn/go-sqlite3*",
        "nuget:microsoft.data.sqlite*", "nuget:system.data.sqlite*",
    )),
    _T("mongodb", "datastore", ("mongodb", "mongo", "mongo db"), (
        "pypi:pymongo", "pypi:motor", "pypi:mongoengine", "pypi:beanie", "py:pymongo",
        "py:motor", "py:mongoengine", "py:beanie", "npm:mongodb", "npm:mongoose",
        "maven:org.mongodb:*", "java:com.mongodb*", "go:go.mongodb.org/mongo-driver*",
        "nuget:mongodb.driver*", "docker:mongo", "docker:mongodb",
        "docker:mongodb-community-server", "terraform:*mongodb/mongodbatlas",
    )),
    _T("cassandra", "datastore", ("cassandra", "apache cassandra", "scylladb", "scylla"), (
        "pypi:cassandra-driver", "py:cassandra", "npm:cassandra-driver",
        "maven:com.datastax.oss:*", "java:com.datastax*", "go:github.com/gocql/gocql*",
        "docker:cassandra", "docker:scylla",
    )),
    _T("dynamodb", "datastore", ("dynamodb", "dynamo db", "amazon dynamodb"), (
        "npm:@aws-sdk/client-dynamodb", "npm:@aws-sdk/lib-dynamodb", "pypi:pynamodb",
        "py:pynamodb", "maven:software.amazon.awssdk:dynamodb*",
    )),
    # ---- caches
    _T("redis", "cache", ("redis", "valkey"), (
        "pypi:redis", "pypi:aioredis", "pypi:redis-py-cluster", "py:redis", "py:aioredis",
        "npm:redis", "npm:ioredis", "maven:redis.clients:jedis", "maven:io.lettuce:*",
        "java:redis.clients*", "java:io.lettuce*", "go:github.com/redis/go-redis*",
        "go:github.com/go-redis/redis*", "go:github.com/gomodule/redigo*",
        "nuget:stackexchange.redis*", "docker:redis", "docker:valkey", "docker:redis-stack*",
        "terraform:*redislabs/rediscloud",
    )),
    _T("memcached", "cache", ("memcached", "memcache"), (
        "pypi:pymemcache", "pypi:python-memcached", "pypi:pylibmc", "py:pymemcache",
        "py:memcache", "py:pylibmc", "npm:memjs", "npm:memcached",
        "go:github.com/bradfitz/gomemcache*", "docker:memcached",
    )),
    # ---- queues / brokers
    _T("kafka", "queue", ("kafka", "apache kafka", "redpanda"), (
        "pypi:kafka-python", "pypi:confluent-kafka", "pypi:aiokafka", "py:kafka",
        "py:confluent_kafka", "py:aiokafka", "npm:kafkajs", "npm:node-rdkafka",
        "maven:org.apache.kafka:*", "maven:org.springframework.kafka:*", "java:org.apache.kafka*",
        "go:github.com/segmentio/kafka-go*", "go:github.com/confluentinc/confluent-kafka-go*",
        "go:github.com/ibm/sarama*", "go:github.com/shopify/sarama*", "nuget:confluent.kafka*",
        "docker:kafka", "docker:cp-kafka", "docker:redpanda",
        "terraform:*confluentinc/confluent", "terraform:*mongey/kafka",
    )),
    _T("rabbitmq", "queue", ("rabbitmq", "rabbit mq", "amqp"), (
        "pypi:pika", "pypi:aio-pika", "pypi:kombu", "py:pika", "py:aio_pika", "py:kombu",
        "npm:amqplib", "npm:amqp-connection-manager", "maven:com.rabbitmq:*",
        "maven:org.springframework.amqp:*", "java:com.rabbitmq*",
        "go:github.com/rabbitmq/amqp091-go*", "go:github.com/streadway/amqp*",
        "nuget:rabbitmq.client*", "docker:rabbitmq",
    )),
    _T("nats", "queue", ("nats", "nats.io"), (
        "pypi:nats-py", "py:nats", "npm:nats", "maven:io.nats:*", "java:io.nats*",
        "go:github.com/nats-io/*", "docker:nats",
    )),
    _T("sqs", "queue", ("sqs", "amazon sqs", "aws sqs"), (
        "npm:@aws-sdk/client-sqs", "maven:software.amazon.awssdk:sqs",
    )),
    _T("celery", "queue", ("celery",), ("pypi:celery", "py:celery")),
    # ---- HTTP clients
    _T("requests", "http-client", ("requests", "python requests"),
       ("pypi:requests", "py:requests")),
    _T("httpx", "http-client", ("httpx",), ("pypi:httpx", "py:httpx")),
    _T("aiohttp", "http-client", ("aiohttp",), ("pypi:aiohttp", "py:aiohttp")),
    _T("urllib3", "http-client", ("urllib3",), ("pypi:urllib3", "py:urllib3")),
    _T("axios", "http-client", ("axios",), ("npm:axios",)),
    _T("node-fetch", "http-client", ("node-fetch",), ("npm:node-fetch", "npm:cross-fetch")),
    _T("got", "http-client", ("got",), ("npm:got",)),
    _T("superagent", "http-client", ("superagent",), ("npm:superagent",)),
    _T("okhttp", "http-client", ("okhttp",), ("maven:com.squareup.okhttp3:*", "java:okhttp3*")),
    _T("resty", "http-client", ("resty",), ("go:github.com/go-resty/resty*",)),
    # ---- web frameworks
    _T("django", "web-framework", ("django",), ("pypi:django", "py:django")),
    _T("flask", "web-framework", ("flask",), ("pypi:flask", "py:flask")),
    _T("fastapi", "web-framework", ("fastapi", "fast api"), ("pypi:fastapi", "py:fastapi")),
    _T("express", "web-framework", ("express", "express.js", "expressjs"), ("npm:express",)),
    _T("koa", "web-framework", ("koa",), ("npm:koa",)),
    _T("fastify", "web-framework", ("fastify",), ("npm:fastify",)),
    _T("nestjs", "web-framework", ("nestjs", "nest.js"), ("npm:@nestjs/*",)),
    _T("spring-boot", "web-framework", ("spring boot", "spring-boot", "spring"), (
        "maven:org.springframework.boot:*", "java:org.springframework*",
    )),
    _T("gin", "web-framework", ("gin",), ("go:github.com/gin-gonic/gin*",)),
    _T("echo", "web-framework", ("echo",), ("go:github.com/labstack/echo*",)),
    _T("fiber", "web-framework", ("fiber",), ("go:github.com/gofiber/fiber*",)),
    # ---- frontend frameworks
    _T("react", "frontend-framework", ("react", "react.js", "reactjs"), ("npm:react",)),
    _T("vue", "frontend-framework", ("vue", "vue.js", "vuejs"), ("npm:vue",)),
    _T("angular", "frontend-framework", ("angular",), ("npm:@angular/core",)),
    _T("svelte", "frontend-framework", ("svelte", "sveltekit"), ("npm:svelte",)),
    _T("solidjs", "frontend-framework", ("solidjs", "solid.js"), ("npm:solid-js",)),
    # ---- ORMs
    _T("sqlalchemy", "orm", ("sqlalchemy",), ("pypi:sqlalchemy", "py:sqlalchemy")),
    _T("peewee", "orm", ("peewee",), ("pypi:peewee", "py:peewee")),
    _T("tortoise-orm", "orm", ("tortoise", "tortoise orm"), ("pypi:tortoise-orm", "py:tortoise")),
    _T("sequelize", "orm", ("sequelize",), ("npm:sequelize",)),
    _T("typeorm", "orm", ("typeorm",), ("npm:typeorm",)),
    _T("prisma", "orm", ("prisma",), ("npm:prisma", "npm:@prisma/client")),
    _T("hibernate", "orm", ("hibernate",), ("maven:org.hibernate*", "java:org.hibernate*")),
    _T("gorm", "orm", ("gorm",), ("go:gorm.io/gorm*", "go:github.com/jinzhu/gorm*")),
    # ---- logging
    _T("structlog", "logging", ("structlog",), ("pypi:structlog", "py:structlog")),
    _T("loguru", "logging", ("loguru",), ("pypi:loguru", "py:loguru")),
    _T("winston", "logging", ("winston",), ("npm:winston",)),
    _T("pino", "logging", ("pino",), ("npm:pino",)),
    _T("bunyan", "logging", ("bunyan",), ("npm:bunyan",)),
    _T("log4j", "logging", ("log4j", "log4j2"), ("maven:org.apache.logging.log4j:*",
                                                 "java:org.apache.logging.log4j*")),
    _T("logback", "logging", ("logback",), ("maven:ch.qos.logback:*", "java:ch.qos.logback*")),
    _T("zap", "logging", ("zap",), ("go:go.uber.org/zap*",)),
    _T("logrus", "logging", ("logrus",), ("go:github.com/sirupsen/logrus*",)),
    _T("serilog", "logging", ("serilog",), ("nuget:serilog*",)),
    # ---- cloud SDKs
    _T("aws-sdk", "cloud-sdk", ("aws sdk", "aws", "amazon web services", "boto"), (
        "pypi:boto3", "pypi:botocore", "pypi:aioboto3", "pypi:boto", "py:boto3", "py:botocore",
        "py:aioboto3", "py:boto", "npm:aws-sdk", "npm:@aws-sdk/*",
        "maven:software.amazon.awssdk:*", "maven:com.amazonaws:*",
        "java:software.amazon.awssdk*", "java:com.amazonaws*", "go:github.com/aws/aws-sdk-go*",
        "nuget:awssdk.*", "terraform:*hashicorp/aws", "terraform:aws",
    )),
    _T("gcp-sdk", "cloud-sdk", ("google cloud sdk", "gcp sdk", "google cloud", "gcp"), (
        "pypi:google-cloud-*", "pypi:google-api-python-client", "py:google.cloud*",
        "py:googleapiclient", "npm:@google-cloud/*", "npm:googleapis",
        "maven:com.google.cloud:*", "java:com.google.cloud*", "go:cloud.google.com/go*",
        "nuget:google.cloud.*", "terraform:*hashicorp/google", "terraform:*hashicorp/google-beta",
        "terraform:google", "terraform:google-beta",
    )),
    _T("azure-sdk", "cloud-sdk", ("azure sdk", "azure"), (
        "pypi:azure-*", "py:azure*", "npm:@azure/*", "maven:com.azure:*",
        "maven:com.microsoft.azure:*", "java:com.azure*", "java:com.microsoft.azure*",
        "go:github.com/azure/azure-sdk-for-go*", "nuget:azure.*", "terraform:*hashicorp/azurerm",
        "terraform:azurerm",
    )),
    # ---- search
    _T("elasticsearch", "search", ("elasticsearch", "elastic search", "opensearch"), (
        "pypi:elasticsearch", "pypi:opensearch-py", "py:elasticsearch", "py:opensearchpy",
        "npm:@elastic/elasticsearch", "npm:@opensearch-project/opensearch",
        "maven:co.elastic.clients:*", "maven:org.elasticsearch*", "java:co.elastic*",
        "java:org.elasticsearch*", "go:github.com/elastic/go-elasticsearch*",
        "docker:elasticsearch", "docker:opensearch", "terraform:*elastic/ec",
        "terraform:*elastic/elasticstack",
    )),
    # ---- vendor (SaaS) SDKs
    _T("stripe", "vendor-sdk", ("stripe",), (
        "pypi:stripe", "py:stripe", "npm:stripe", "maven:com.stripe:*", "java:com.stripe*",
        "go:github.com/stripe/stripe-go*", "nuget:stripe.net",
    )),
    _T("twilio", "vendor-sdk", ("twilio",), (
        "pypi:twilio", "py:twilio", "npm:twilio", "maven:com.twilio.sdk:*", "java:com.twilio*",
        "go:github.com/twilio/twilio-go*", "nuget:twilio",
    )),
    _T("sendgrid", "vendor-sdk", ("sendgrid",), (
        "pypi:sendgrid", "py:sendgrid", "npm:@sendgrid/*", "maven:com.sendgrid:*",
        "java:com.sendgrid*", "go:github.com/sendgrid/*", "nuget:sendgrid*",
    )),
    _T("sentry", "vendor-sdk", ("sentry",), (
        "pypi:sentry-sdk", "py:sentry_sdk", "npm:@sentry/*", "maven:io.sentry:*", "java:io.sentry*",
        "go:github.com/getsentry/sentry-go*", "nuget:sentry*", "terraform:*jianyuan/sentry",
    )),
    _T("datadog", "vendor-sdk", ("datadog",), (
        "pypi:ddtrace", "pypi:datadog", "py:ddtrace", "py:datadog", "npm:dd-trace",
        "maven:com.datadoghq:*", "go:github.com/datadog/*", "go:gopkg.in/datadog/*",
        "terraform:*datadog/datadog",
    )),
    _T("openai", "vendor-sdk", ("openai",), (
        "pypi:openai", "py:openai", "npm:openai", "go:github.com/sashabaranov/go-openai*",
    )),
    _T("anthropic", "vendor-sdk", ("anthropic",), (
        "pypi:anthropic", "py:anthropic", "npm:@anthropic-ai/sdk",
    )),
]  # fmt: skip

# Words that are never matched literally (languages, protocols, plain words): a claim
# about "Go" or "REST" is not a claim about a package called "go" or "rest".
NOT_LITERAL = frozenset(
    """go golang python java javascript js typescript ts rust kotlin c c++ c# csharp ruby php
    scala swift elixir erlang haskell clojure perl lua dart bash shell sql nosql rest grpc
    graphql http https tcp udp json yaml xml toml csv utf-8 utf8 ascii unicode markdown html
    css docker kubernetes k8s terraform helm linux windows macos code service services api apis
    module modules package packages library libraries framework frameworks tool tools data
    database databases system systems app apps application applications server servers client
    clients layer layers it this that none""".split()
)

_GENERIC_TAIL = re.compile(
    r"\s+(?:library|libraries|lib|libs|package|packages|module|modules|client|clients|driver|"
    r"drivers|sdk|sdks|framework|frameworks|dependency|dependencies|server|servers|"
    r"database|databases|db|engine|broker|service|instance|instances|cluster|imports?)$"
)
# Only these tails may be dropped before a *literal* match: "the requests library"
# names the package requests, "the payments database" does not name a package payments.
_SOFTWARE_TAIL = re.compile(
    r"\s+(?:library|lib|package|module|client|driver|sdk|dependency|imports?)$"
)
_LITERAL_TERM = re.compile(r"^@?[a-z0-9][a-z0-9._\-/@:+]*$")
_FILLER_PARTS = frozenset("as to of and or for the a an in on with by".split())


# --------------------------------------------------------------------------- registry


def _norm(term: str) -> str:
    t = term.lower().strip().strip("`'\".,;:!?()[]{}")
    return " ".join(t.split())


_BY_ID: dict[str, Technology] = {}
_BY_ALIAS: dict[str, Technology] = {}
_CATEGORY_BY_PHRASE: dict[str, str] = {}


def register_category(category: str, phrases: Iterable[str] = ()) -> None:
    """Add (or extend) a category and the phrases that name it."""
    existing = CATEGORIES.get(category, ())
    merged = tuple(dict.fromkeys((*existing, *phrases, category)))
    CATEGORIES[category] = merged
    for p in merged:
        _CATEGORY_BY_PHRASE[_norm(p)] = category


def register_technology(tech: Technology, *, replace: bool = False) -> None:
    """Add a technology. Its aliases (and id) resolve to it; an existing id or alias
    is an error unless ``replace``."""
    if tech.category is not None and tech.category not in CATEGORIES:
        raise ValueError(f"{tech.id}: unknown category {tech.category!r}; register it first")
    if tech.id in _BY_ID and not replace:
        raise ValueError(f"duplicate technology id {tech.id!r}")
    for a in (tech.id, *tech.aliases):
        owner = _BY_ALIAS.get(_norm(a))
        if owner is not None and owner.id != tech.id and not replace:
            raise ValueError(f"alias {a!r} of {tech.id} already names {owner.id}")
    if tech.id in _BY_ID:
        TECHNOLOGIES[:] = [t for t in TECHNOLOGIES if t.id != tech.id]
    if tech not in TECHNOLOGIES:
        TECHNOLOGIES.append(tech)
    _BY_ID[tech.id] = tech
    for a in (tech.id, *tech.aliases):
        _BY_ALIAS[_norm(a)] = tech


def _build() -> None:
    for cat, phrases in list(CATEGORIES.items()):
        register_category(cat, phrases)
    initial = list(TECHNOLOGIES)
    TECHNOLOGIES.clear()
    for t in initial:
        register_technology(t)


_build()


def technology(tech_id: str) -> Technology | None:
    return _BY_ID.get(tech_id)


def members(category: str) -> list[Technology]:
    """Every catalog technology of ``category``."""
    return [t for t in TECHNOLOGIES if t.category == category]


# --------------------------------------------------------------------------- resolution


def _variants(term: str) -> list[str]:
    """``term`` plus its singular form and the form without a generic tail word
    ("the requests library" -> "requests", "Cloud SDKs" -> "cloud sdk")."""
    out = [term]
    for t in list(out):
        if t.endswith("ies") and len(t) > 4:
            out.append(t[:-3] + "y")
        elif t.endswith("s") and not t.endswith("ss") and len(t) > 3:
            out.append(t[:-1])
    for t in list(out):
        stripped = _GENERIC_TAIL.sub("", t)
        if stripped != t and stripped:
            out.append(stripped)
    return list(dict.fromkeys(out))


def category_for(phrase: str | None) -> str | None:
    """Category id named by ``phrase`` ("datastores", "the message broker"), or None."""
    if not phrase:
        return None
    t = re.sub(r"^(?:the|a|an|our|any|other|another|all)\s+", "", _norm(phrase))
    for v in _variants(t):
        if v in _CATEGORY_BY_PHRASE:
            return _CATEGORY_BY_PHRASE[v]
    return None


def literal_technology(term: str) -> Technology | None:
    """A pseudo-technology that matches ``term`` literally as a package/import name,
    or None if ``term`` does not look like a package name."""
    t = _norm(term)
    if not _LITERAL_TERM.match(t) or t in NOT_LITERAL:
        return None
    parts = re.split(r"[-_]", t)
    if len(parts) > 1 and any(p in _FILLER_PARTS for p in parts):
        return None  # "cache-as-database" is prose, not a package
    py = t.replace("-", "_")
    return Technology(
        id=t,
        category=None,
        aliases=(t,),
        patterns=(
            f"pypi:{t}", f"py:{py}", f"py:{py}.*", f"npm:{t}", f"go:{t}", f"go:{t}/*",
            f"maven:{t}", f"maven:*:{t}", f"java:{t}", f"java:{t}.*", f"nuget:{t}",
            f"docker:{t}", f"terraform:{t}", f"terraform:*/{t}",
        ),
        literal=True,
    )  # fmt: skip


def resolve(term: str) -> Resolution | None:
    """Resolve a claim term: a catalog technology (by alias), a category, or a literal
    package name. None when it is none of these."""
    t = re.sub(r"^(?:the|a|an|our|any|all)\s+", "", _norm(term))
    if not t:
        return None
    for v in _variants(t):
        tech = _BY_ALIAS.get(v)
        if tech is not None:
            return Resolution(term, "technology", (tech,), tech.category)
    cat = category_for(t)
    if cat is not None:
        return Resolution(term, "category", tuple(members(cat)), cat)
    for v in dict.fromkeys((t, _SOFTWARE_TAIL.sub("", t))):
        lit = literal_technology(v)
        if lit is not None:
            return Resolution(term, "literal", (lit,), None)
    return None


# --------------------------------------------------------------------------- matching


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _docker_names(image: str) -> list[str]:
    n = image.lower().split("@", 1)[0]
    last = n.rsplit("/", 1)[-1]
    if ":" in last:  # tag
        n = n[: len(n) - len(last)] + last.split(":", 1)[0]
        last = last.split(":", 1)[0]
    return list(dict.fromkeys([last, n]))


def name_matches(tech: Technology, namespace: str, names: Iterable[str]) -> bool:
    """True if any of ``names`` matches one of ``tech``'s globs in ``namespace``."""
    globs = tech.globs(namespace)
    if not globs:
        return False
    for raw in names:
        if not raw:
            continue
        cands = [raw.lower()]
        if namespace == "pypi":
            cands = [_pep503(raw)]
        elif namespace == "docker":
            cands = _docker_names(raw)
        for g in globs:
            g2 = _pep503(g.replace("*", "\0")).replace("\0", "*") if namespace == "pypi" else g
            if any(fnmatch.fnmatchcase(c, g2.lower()) for c in cands):
                return True
    return False


# Dependency ecosystem (DependencyRef.ecosystem) -> catalog namespace.
ECOSYSTEM_NAMESPACE = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "gradle-plugin": "maven",
    "go": "go",
    "nuget": "nuget",
    "dotnet-sdk": "nuget",
    "docker": "docker",
    "terraform": "terraform",
    "terraform-provider": "terraform",
    "terraform-module": "terraform",
}

# Import language -> catalog namespace.
LANGUAGE_NAMESPACE = {
    "python": "py",
    "javascript": "npm",
    "typescript": "npm",
    "java": "java",
    "go": "go",
}
