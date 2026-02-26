# Design Document: Zappa -- Serverless Python on AWS Lambda

**Repository:** SpareFoot/Zappa-1
**Version:** 0.54.0
**Branch:** `enhancements/snyk_vulnerability_fixes/02/DATA-1431`
**Jira:** DATA-1431
**Last Updated:** 2026-02-24

---

## Table of Contents

1. [What Is Zappa](#1-what-is-zappa)
2. [Business Problem This Branch Solves](#2-business-problem-this-branch-solves)
3. [Architecture Overview](#3-architecture-overview)
4. [Core Components -- File-by-File](#4-core-components----file-by-file)
5. [How a Deployment Works](#5-how-a-deployment-works)
6. [How an HTTP Request Is Handled at Runtime](#6-how-an-http-request-is-handled-at-runtime)
7. [How Async / Event-Driven Invocations Work](#7-how-async--event-driven-invocations-work)
8. [What Changed on This Branch (DATA-1431)](#8-what-changed-on-this-branch-data-1431)
9. [Security Model](#9-security-model)
10. [Configuration Reference](#10-configuration-reference)
11. [Test Infrastructure](#11-test-infrastructure)
12. [Known Side Effects & Rollback](#12-known-side-effects--rollback)

---

## 1. What Is Zappa

Zappa is a **serverless deployment framework** for Python WSGI applications. It lets developers run standard Flask, Django, Bottle, or Pyramid web apps on **AWS Lambda + API Gateway** without managing servers.

The core value proposition:

- **`zappa deploy production`** packages the app, uploads it to S3, creates a Lambda function, wires API Gateway, and returns a live URL.
- **`zappa update production`** deploys new code with zero downtime.
- At runtime, API Gateway forwards HTTP requests to Lambda. Zappa translates the API Gateway event into a standard WSGI `environ` dict, calls the app, and translates the response back.

Zappa also supports scheduled tasks (via CloudWatch Events), async background jobs (via Lambda self-invocation or SNS), event-driven processing (S3, SQS, DynamoDB Streams, Kinesis), Let's Encrypt SSL, and Django management commands.

---

## 2. Business Problem This Branch Solves

### The Problem

The SpareFoot fork of Zappa (v0.53.0) accumulated **143 open Snyk vulnerabilities**:

| Category | Count | Root Cause |
|----------|-------|------------|
| Dependency vulnerabilities (Open Source) | 130+ | Severely outdated pins -- Werkzeug 0.16.1, Django 3.1.7, certifi 2020.12.5, urllib3 1.26.4 |
| Source code vulnerabilities (SAST) | 13 | Missing input validation on file paths and archive extraction |

Several of these are **Critical** (CVSS 9.8): SQL injection in Django, certificate trust chain issues in certifi, and remote code execution in Werkzeug. The codebase also carried dead Python 2/3 compatibility layers (`future`, `six`) that themselves have known CVEs.

### How This Branch Fixes It

The branch applies a systematic 7-step remediation:

1. **Upgrade all dependencies** to versions that resolve known CVEs.
2. **Remove `future` and `six`** (Python 2/3 shims) -- they carry CVEs and are unnecessary on Python 3.10+.
3. **Fix 8 path traversal vulnerabilities** (CWE-23) in `core.py` by adding `validate_path_within_directory()` checks.
4. **Fix tar slip vulnerability** (CWE-22) in `handler.py` by adding `_safe_tar_extract()` validation.
5. **Replace SHA-1 with SHA-256** (CWE-916) in `core.py` for file checksums.
6. **Fix debug mode** (CWE-489) in the example app and **reflected XSS** (CWE-79) in a test helper.
7. **Raise minimum Python to 3.10** and modernize the test framework from `nose` to `pytest`.

All 143 Snyk issues are resolved. The full CVE cross-reference is in `SNYK_REMEDIATION_PLAN.md`.

---

## 3. Architecture Overview

```
                      DEPLOY-TIME                              RUN-TIME
                      ──────────                              ─────────

  Developer                                     Client HTTP Request
      │                                                │
  $ zappa deploy                               API Gateway / ALB
      │                                                │
 ┌────▼────────────┐                          ┌────────▼──────────┐
 │   cli.py        │                          │   AWS Lambda      │
 │  (CLI parser,   │                          │                   │
 │   settings)     │                          │  handler.py       │
 └────┬────────────┘                          │  (entry point)    │
      │                                       └────────┬──────────┘
 ┌────▼────────────┐                                   │
 │   core.py       │                          ┌────────▼──────────┐
 │  (packaging,    │                          │   wsgi.py         │
 │   S3 upload,    │                          │  (event → WSGI    │
 │   Lambda CRUD,  │                          │   environ)        │
 │   API Gateway)  │                          └────────┬──────────┘
 └────┬────────────┘                                   │
      │                                       ┌────────▼──────────┐
 ┌────▼────────────┐                          │   middleware.py   │
 │   AWS Services  │                          │  (Set-Cookie fix) │
 │  S3, Lambda,    │                          └────────┬──────────┘
 │  API Gateway,   │                                   │
 │  IAM, CW       │                          ┌────────▼──────────┐
 └─────────────────┘                          │   Your WSGI App   │
                                              │  (Flask / Django) │
                                              └───────────────────┘

  Shared utilities: utilities.py
  Async tasks:      asynchronous.py
  SSL certs:        letsencrypt.py
  Django bootstrap: ext/django_zappa.py
```

**Deploy-time** components (`cli.py`, `core.py`) run on the developer's machine. They package code, upload to S3, and create/update AWS resources via boto3.

**Run-time** components (`handler.py`, `wsgi.py`, `middleware.py`) execute inside AWS Lambda. They receive API Gateway events, translate them to WSGI, call the app, and return responses.

---

## 4. Core Components -- File-by-File

### 4.1 `zappa/handler.py` -- Lambda Entry Point

**What it does:** This is the function AWS Lambda invokes. It receives every event -- HTTP requests, scheduled events, SNS/SQS messages, S3 notifications, management commands -- and routes them to the correct handler.

**Key concepts:**

- **Singleton pattern:** `LambdaHandler` initializes once per Lambda container (cold start), then reuses the instance for subsequent warm invocations. This amortizes the cost of loading the WSGI app.
- **Event routing:** The `handler()` method inspects the event structure to determine the type (HTTP, scheduled, command, AWS event record, Lex, Cognito, etc.) and dispatches accordingly.
- **WSGI execution:** For HTTP requests, it calls `create_wsgi_request()` from `wsgi.py` to build the WSGI environ, then calls `Response.from_app(self.wsgi_app, environ)` to run the app.
- **S3 project loading:** Optionally downloads a project archive from S3 at cold start and extracts it to `/tmp`. This is where the tar slip fix applies.

**Critical functions:**

| Function | Purpose |
|----------|---------|
| `lambda_handler(event, context)` | AWS Lambda entry point. Creates singleton, delegates to `handler()`. |
| `handler(event, context)` | Core routing logic. Determines event type, dispatches to WSGI or event handler. |
| `_safe_tar_extract(tar, dest_path)` | **[NEW on this branch]** Validates all tar members resolve within the destination directory before extracting. Prevents CWE-22 (tar slip). |

**Security change on this branch:** Added `_safe_tar_extract()` to validate tar member paths. Removed `from builtins import str` (dead Python 2 import from `future` package).

---

### 4.2 `zappa/core.py` -- Deployment Orchestration Engine

**What it does:** This is the largest file (~3,600 lines). It contains the `Zappa` class that orchestrates all AWS interactions: packaging the deployment zip, uploading to S3, creating/updating Lambda functions, configuring API Gateway, managing IAM roles, and handling scheduled events.

**Key concepts:**

- **Packaging pipeline:** `create_lambda_zip()` copies the app source, virtualenv site-packages, and compiled C extensions (via manylinux wheels from PyPI) into a zip archive. This zip becomes the Lambda deployment package.
- **Manylinux wheel resolution:** `get_manylinux_wheel_url()` queries PyPI for precompiled Linux wheels for packages with C extensions (e.g., `cryptography`, `numpy`). The ABI tag generation was fixed on this branch for Python 3.10+ (two-digit minor versions).
- **API Gateway wiring:** Creates REST API resources, methods, integrations, and deployments to route HTTP traffic to the Lambda function.

**Critical functions:**

| Function | Purpose |
|----------|---------|
| `create_lambda_zip()` | Packages app + dependencies into a Lambda-compatible zip. This is where most path traversal fixes apply. |
| `upload_to_s3()` | Uploads the zip to the configured S3 bucket. |
| `create_lambda_function()` | Creates a new Lambda function pointing to the S3 zip. |
| `update_lambda_function()` | Updates an existing function's code. |
| `create_api_gateway_routes()` | Wires API Gateway to the Lambda function. |
| `get_manylinux_wheel_url()` | Resolves manylinux wheels from PyPI for C extensions. |

**Security changes on this branch:**

- **Path traversal (CWE-23):** Added `validate_path_within_directory()` checks at 8 locations where file paths from external sources (egg-link files, zip members, glob results) are used to read, write, or delete files.
- **Zip extraction traversal:** Validates all zip members resolve within the target directory before calling `extractall()`.
- **SHA-1 → SHA-256 (CWE-916):** Changed `hashlib.sha1()` to `hashlib.sha256()` for generating CloudWatch rule name hashes.
- **Manylinux ABI fix:** Fixed `sys.maxint` → `sys.maxsize` for Python 3.10+ compatibility.
- **PyPI 404 handling:** Added graceful error handling when manylinux wheels are not found on PyPI.
- **Removed:** `from builtins import bytes, int` and `import distutils` (both deprecated/removed in modern Python).

---

### 4.3 `zappa/cli.py` -- Command-Line Interface

**What it does:** The user-facing CLI. Parses arguments, loads `zappa_settings.json` (or YAML/TOML), validates configuration, and dispatches commands to the `Zappa` core class.

**Key commands:**

| Command | What It Does |
|---------|-------------|
| `zappa init` | Interactive setup wizard. Detects Flask/Django, creates `zappa_settings.json`. |
| `zappa deploy <stage>` | Full initial deployment: package → upload → create Lambda → create API Gateway. |
| `zappa update <stage>` | Update existing deployment with new code. |
| `zappa undeploy <stage>` | Tear down Lambda, API Gateway, and related resources. |
| `zappa rollback <stage> -n <N>` | Roll back to the Nth previous deployment version. |
| `zappa schedule <stage>` | Configure CloudWatch Events for scheduled tasks. |
| `zappa invoke <stage> <function>` | Invoke a function remotely. |
| `zappa manage <stage> <command>` | Run Django management commands in Lambda. |
| `zappa tail <stage>` | Stream CloudWatch logs. |
| `zappa certify <stage>` | Provision/renew SSL certificates via Let's Encrypt. |
| `zappa status <stage>` | Show deployment status and resource info. |

**Security change on this branch:** Removed `from builtins import bytes, input` and `from past.builtins import basestring`. Replaced `isinstance(v, basestring)` with `isinstance(v, str)`.

---

### 4.4 `zappa/wsgi.py` -- API Gateway Event → WSGI Translation

**What it does:** Translates an API Gateway (or ALB) event dictionary into a PEP 3333 WSGI `environ` dictionary that any WSGI framework (Flask, Django, etc.) can consume.

**Key functions:**

| Function | Purpose |
|----------|---------|
| `create_wsgi_request(event_info, ...)` | Builds the WSGI `environ` from the API Gateway event. Handles method, path, headers, query string, body, multi-value params, remote IP extraction, binary payloads, and API Gateway context forwarding. |
| `common_log(environ, response, response_time)` | Logs each request in Apache Common Log Format. |

**Security change on this branch:** Replaced `werkzeug.urls.url_unquote()` with `urllib.parse.unquote()` (Python stdlib). This was the **only code change** required to unblock the Werkzeug 0.16.1 → 3.0.6 upgrade. Also replaced `six.string_types` with `str` and `six.BytesIO` with `io.BytesIO`.

---

### 4.5 `zappa/utilities.py` -- Shared Utilities

**What it does:** Helper functions used across the codebase. App detection (Flask/Django), path manipulation, S3 URL parsing, event source management.

**Critical functions:**

| Function | Purpose |
|----------|---------|
| `validate_path_within_directory(path, directory)` | **[NEW on this branch]** Resolves both paths via `os.path.realpath()` and asserts the target path starts with the directory prefix. Raises `ValueError` on traversal attempts. Used by `core.py` and `handler.py` to prevent CWE-22 and CWE-23. |
| `copytree(src, dst, ...)` | Recursive directory copy with symlink and metadata handling. |
| `detect_django_settings()` | Walks the project to find Django settings modules. |
| `detect_flask_apps()` | Searches for Flask `app = Flask(...)` patterns. |
| `parse_s3_url(url)` | Parses `s3://bucket/key` URLs into (bucket, key) tuples. |
| `get_runtime_from_python_version()` | Maps the current Python version to an AWS Lambda runtime identifier. |

**Security change on this branch:** Added `validate_path_within_directory()`. Removed `from past.builtins import basestring`, replaced `isinstance(name, basestring)` with `isinstance(name, str)`.

---

### 4.6 `zappa/middleware.py` -- WSGI Middleware

**What it does:** Solves a specific AWS API Gateway limitation: API Gateway collapses duplicate HTTP headers with the same name. Since web apps routinely set multiple `Set-Cookie` headers, Zappa works around this by generating all case permutations of the string "set-cookie" (e.g., `Set-Cookie`, `set-Cookie`, `sEt-Cookie`, etc.) so each cookie gets a distinct header name that API Gateway treats as separate headers.

**Key class:** `ZappaWSGIMiddleware` wraps the WSGI app and intercepts the response to apply this Set-Cookie permutation.

**No changes on this branch.**

---

### 4.7 `zappa/asynchronous.py` -- Background Task Execution

**What it does:** Provides a `@task` decorator that makes any function execute asynchronously. When a decorated function is called, instead of running locally, Zappa serializes the call and invokes a new Lambda instance (or publishes to SNS) to run it in the background.

**Usage:**
```python
from zappa.asynchronous import task

@task
def send_welcome_email(user_id):
    # Runs in a separate Lambda invocation
    ...

# Returns immediately -- execution happens in background
send_welcome_email(user_id=42)
```

**Key constraint:** The decorated function must be importable by module path (no closures, no lambdas), and all arguments must be JSON-serializable.

**No changes on this branch.**

---

### 4.8 `zappa/__init__.py` -- Version & Python Gate

**What it does:** Declares the package version and validates the Python runtime. If the running Python version is not in `SUPPORTED_VERSIONS`, it raises `RuntimeError` with a clear message.

**Change on this branch:** Bumped version from 0.53.0 to 0.54.0. Updated `SUPPORTED_VERSIONS` from `[(3, 6), (3, 7), (3, 8)]` to `[(3, 10), (3, 11), (3, 12), (3, 13)]`.

---

### 4.9 `zappa/letsencrypt.py` -- SSL Certificate Management

**What it does:** Automates SSL certificate provisioning via Let's Encrypt using the DNS-01 ACME challenge. It creates a domain key, generates a CSR, registers with Let's Encrypt, creates Route 53 DNS records for domain validation, obtains the signed certificate, and uploads it to IAM/ACM for use with API Gateway custom domains.

**No changes on this branch.**

---

### 4.10 `zappa/ext/django_zappa.py` -- Django Bootstrap

**What it does:** A small helper that bootstraps Django for Lambda execution. Sets `DJANGO_SETTINGS_MODULE`, calls `django.setup()`, and returns the WSGI application via `get_wsgi_application()`.

**No changes on this branch.**

---

## 5. How a Deployment Works

```
Developer runs: zappa deploy production
                        │
                        ▼
              ┌─────────────────────┐
              │  cli.py             │
              │  1. Parse command   │
              │  2. Load settings   │
              │  3. Validate config │
              └────────┬────────────┘
                       │
                       ▼
              ┌─────────────────────┐
              │  core.py            │
              │  create_lambda_zip()│
              │                     │
              │  1. Create temp dir │
              │  2. Copy app source │
              │  3. Copy site-pkgs  │
              │  4. Fetch manylinux │
              │     wheels (PyPI)   │
              │  5. Validate paths  │ ← CWE-23 fixes here
              │  6. Build .zip      │
              └────────┬────────────┘
                       │
                       ▼
              ┌─────────────────────┐
              │  core.py            │
              │  upload_to_s3()     │
              │                     │
              │  SHA-256 checksum   │ ← Was SHA-1, now SHA-256
              │  Upload to S3       │
              └────────┬────────────┘
                       │
                       ▼
              ┌─────────────────────────────┐
              │  core.py                    │
              │  create_lambda_function()   │
              │                             │
              │  1. Create IAM role         │
              │  2. Create Lambda function  │
              │     Handler: zappa.handler  │
              │     .lambda_handler         │
              │  3. Create API Gateway      │
              │  4. Wire routes → Lambda    │
              │  5. Deploy API stage        │
              │  6. Return public URL       │
              └─────────────────────────────┘
```

---

## 6. How an HTTP Request Is Handled at Runtime

```
Client: GET /api/users/123
              │
              ▼
        API Gateway
              │
              ▼ (Lambda Proxy Integration)
  ┌───────────────────────────────────────────┐
  │  handler.py :: lambda_handler(event, ctx) │
  │                                           │
  │  event = {                                │
  │    "httpMethod": "GET",                   │
  │    "path": "/api/users/123",              │
  │    "headers": { ... },                    │
  │    "queryStringParameters": { ... },      │
  │    "body": null                           │
  │  }                                        │
  └──────────────┬────────────────────────────┘
                 │
                 ▼
  ┌───────────────────────────────────────────┐
  │  wsgi.py :: create_wsgi_request(event)    │
  │                                           │
  │  Builds WSGI environ dict:               │
  │    REQUEST_METHOD = "GET"                 │
  │    PATH_INFO = "/api/users/123"           │
  │    HTTP_HOST = "xyz.execute-api..."       │
  │    QUERY_STRING = ""                      │
  │    wsgi.input = <empty BytesIO>           │
  │    REMOTE_ADDR = <from X-Forwarded-For>   │
  └──────────────┬────────────────────────────┘
                 │
                 ▼
  ┌───────────────────────────────────────────┐
  │  middleware.py :: ZappaWSGIMiddleware      │
  │                                           │
  │  Wraps response to permute Set-Cookie     │
  │  header casing for API Gateway compat     │
  └──────────────┬────────────────────────────┘
                 │
                 ▼
  ┌───────────────────────────────────────────┐
  │  Your Flask / Django App                  │
  │                                           │
  │  Processes request normally.              │
  │  Returns WSGI response.                   │
  └──────────────┬────────────────────────────┘
                 │
                 ▼
  ┌───────────────────────────────────────────┐
  │  handler.py :: response transformation    │
  │                                           │
  │  return {                                 │
  │    "statusCode": 200,                     │
  │    "body": "{\"id\": 123, ...}",          │
  │    "headers": { ... }                     │
  │  }                                        │
  └───────────────────────────────────────────┘
              │
              ▼
        API Gateway → Client
```

---

## 7. How Async / Event-Driven Invocations Work

### Async Tasks (`@task` decorator)

```python
@task
def process_report(report_id):
    ...

process_report(42)  # Returns immediately
```

Under the hood:
1. Zappa serializes the function path (`mymodule.process_report`) and args (`[42]`) into JSON.
2. Invokes the **same Lambda function** with `InvocationType=Event` (async), passing:
   ```json
   {"command": "zappa.asynchronous.route_lambda_task", "task_path": "mymodule.process_report", "args": [42]}
   ```
3. A new Lambda instance receives this event, `handler.py` detects the `command` key, imports the function, and calls it.

### AWS Event Sources (S3, SNS, SQS, DynamoDB, Kinesis)

1. The event arrives with a `Records` array.
2. `handler.py` extracts the event source ARN from the first record.
3. Looks up the mapped function from `zappa_settings`.
4. Dynamically imports and calls the function with the event and context.

---

## 8. What Changed on This Branch (DATA-1431)

### 8.1 Commit-by-Commit Summary

Commits are listed oldest-first (bottom of branch to tip):

| # | File(s) | What Changed | Why |
|---|---------|-------------|-----|
| 1 | `Makefile` | Replace `nosetests` → `pytest` | `nose` is unmaintained; pytest is the standard |
| 2 | `example/app.py` | `debug=True` → `debug=False` | CWE-489: debug mode exposes internals |
| 3 | `example/requirements.txt` | Flask >=3.0, zappa >=0.54.0 | Align example with upgraded deps |
| 4 | `requirements.in` | Upgrade Werkzeug, requests, certifi, urllib3, etc.; remove `future`, `six` | Resolve 130+ dependency CVEs |
| 5 | `requirements.txt` | Recompile via `pip-compile` | Lock upgraded dependency graph |
| 6 | `setup.py` | `python_requires='>=3.10,<3.14'`, update classifiers | Drop EOL Python versions |
| 7 | `test.sh` | `nosetests` → `pytest` | Test runner migration |
| 8 | `test_requirements.in` | Django >=4.2, Flask >=3.0, `nose` → `pytest` | Resolve test-dep CVEs |
| 9 | `test_requirements.txt` | Recompile | Lock test dependency graph |
| 10 | `tests/test_event_script_app.py` | Whitespace fix | Formatting |
| 11 | `tests/test_wsgi_script_name_app.py` | Return `Response(..., content_type="text/plain")` | CWE-79: reflected XSS |
| 12 | `tests/tests.py` | Update manylinux tests for 3.10-3.13; fix pytest compat | Stale tests for removed Python versions |
| 13 | `tests/tests_docs.py` | `assertEquals` → `assertEqual` | Removed in Python 3.12 |
| 14 | `zappa/__init__.py` | Version 0.54.0; `SUPPORTED_VERSIONS` = 3.10-3.13 | Drop EOL, support current Lambda runtimes |
| 15 | `zappa/cli.py` | Remove `builtins`/`past.builtins` imports; `basestring` → `str` | Remove `future`/`six` dependency |
| 16 | `zappa/core.py` | Path traversal fixes (8 locs), zip validation, SHA-256, manylinux ABI fix, PyPI 404 handling, remove `distutils`/`builtins` | CWE-23, CWE-916, Python 3.10+ compat |
| 17 | `zappa/handler.py` | Add `_safe_tar_extract()`; remove `builtins` import | CWE-22: tar slip |
| 18 | `zappa/utilities.py` | Add `validate_path_within_directory()`; remove `past.builtins`; `basestring` → `str` | CWE-23 prevention utility |
| 19 | `zappa/wsgi.py` | `werkzeug.urls.url_unquote` → `urllib.parse.unquote`; remove `six`; `io.BytesIO` | Unblock Werkzeug 3.x upgrade |

### 8.2 SAST Fixes in Detail

#### CWE-22: Tar Slip (`handler.py`)

**Before:** Raw `tar.extractall(project_folder)` on an S3-downloaded archive with no member validation.

**After:** `_safe_tar_extract()` iterates all tar members, resolves each path via `os.path.realpath()`, and rejects any member whose resolved path falls outside the destination directory.

#### CWE-23: Path Traversal (`core.py`, 8 locations)

**Before:** Paths derived from egg-link files, zip members, and glob patterns were used directly in file operations (`copytree`, `os.remove`, `shutil.rmtree`, `extractall`) without validation.

**After:** Each path is passed through `validate_path_within_directory()` (from `utilities.py`) before any file operation. If the resolved path escapes the expected directory, a `ValueError` is raised.

#### CWE-916: Weak Hash (`core.py`)

**Before:** `hashlib.sha1(name.encode(...)).hexdigest()` for CloudWatch rule naming.

**After:** `hashlib.sha256(...)`. The hex digest is longer (64 chars vs 40) but the downstream consumer (`get_event_name`) already truncates, so no functional impact.

#### CWE-489: Debug Mode (`example/app.py`)

**Before:** `app.run(debug=True)`.

**After:** `app.run(debug=False)`.

#### CWE-79: Reflected XSS (`tests/test_wsgi_script_name_app.py`)

**Before:** Flask route returned `request.url` as HTML.

**After:** Returns `Response(request.url, content_type="text/plain")`.

### 8.3 Dependency Removals

| Package | Why Removed |
|---------|------------|
| `future` | CVE-2022-40899 (ReDoS). Python 2/3 shim unnecessary on Python 3.10+. |
| `six` | Python 2/3 shim. Only used for `string_types` and `BytesIO`, both trivially replaced with stdlib equivalents. |

### 8.4 Key Dependency Upgrades

| Package | Before | After | Critical CVE Fixed |
|---------|--------|-------|--------------------|
| Werkzeug | 0.16.1 | >=3.0.6 | CVE-2024-34069 (RCE) |
| Django (test) | 3.1.7 | >=4.2 | CVE-2022-34265 (SQL Injection, CVSS 9.8) |
| certifi | 2020.12.5 | >=2024.7.4 | CVE-2023-37920 (Trust Chain, CVSS 9.8) |
| Flask (test) | 1.1.2 | >=3.0 | CVE-2023-30861 (Info Exposure) |
| requests | 2.25.1 | >=2.32.0 | Multiple |
| urllib3 | 1.26.4 | >=1.26.18 | Multiple |

---

## 9. Security Model

### 9.1 Archive Extraction (Deploy-Time & Runtime)

All archive extraction (zip and tar) now follows a two-step pattern:

1. **Validate:** Iterate all members, resolve each path via `os.path.realpath()`, assert it falls within the target directory.
2. **Extract:** Only after all members pass validation.

This prevents directory traversal attacks where a malicious archive member like `../../etc/cron.d/backdoor` could write files outside the intended directory.

### 9.2 Path Validation Utility

`utilities.py:validate_path_within_directory(path, directory)` is the single point of enforcement. It:
- Resolves symlinks (`os.path.realpath`)
- Normalizes `..` components
- Checks the resolved path starts with the resolved directory prefix
- Raises `ValueError` with a descriptive message on violation

### 9.3 Cryptographic Standards

- SHA-256 for all file checksums (no SHA-1 anywhere in the codebase)
- TLS via API Gateway (managed by AWS)
- Let's Encrypt certificates for custom domains

---

## 10. Configuration Reference

Zappa is configured via `zappa_settings.json` (or `.yaml` / `.toml`) at the project root. Each top-level key is a deployment stage (e.g., `dev`, `production`).

Key settings a reviewer should know about:

| Setting | Type | Purpose |
|---------|------|---------|
| `app_function` | `str` | Module path to the WSGI app (e.g., `"app.app"` for Flask) |
| `django_settings` | `str` | Module path to Django settings (alternative to `app_function`) |
| `s3_bucket` | `str` | S3 bucket for deployment packages |
| `aws_region` | `str` | AWS region |
| `runtime` | `str` | Lambda runtime (e.g., `python3.11`) |
| `memory_size` | `int` | Lambda memory in MB (128-10240) |
| `timeout_seconds` | `int` | Lambda timeout in seconds (1-900) |
| `environment_variables` | `dict` | Environment variables injected into Lambda |
| `vpc_config` | `dict` | VPC subnet and security group IDs |
| `events` | `list` | Scheduled events (CloudWatch Events) |
| `keep_warm` | `bool` | Prevent cold starts via periodic pings |
| `slim_handler` | `bool` | Upload large packages to S3 and download at cold start (where tar slip fix applies) |
| `extends` | `str` | Inherit settings from another stage |

---

## 11. Test Infrastructure

### Test Framework

Tests were migrated from `nose` (unmaintained since 2015) to `pytest`.

### Test Files

| File | What It Tests |
|------|--------------|
| `tests/tests.py` | Core integration: packaging, deployment, CLI, API Gateway, scheduling |
| `tests/test_handler.py` | Lambda handler: event routing, WSGI request creation, response formatting |
| `tests/tests_async.py` | Async task decorator: Lambda and SNS dispatch |
| `tests/tests_middleware.py` | WSGI middleware: Set-Cookie permutation |
| `tests/tests_placebo.py` | Mocked AWS API calls via `placebo` |
| `tests/tests_docs.py` | Documentation validation |

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_handler.py -v

# With coverage
pytest --cov=zappa
```

---

## 12. Known Side Effects & Rollback

### Side Effects of This Branch

1. **CloudWatch rule names change:** SHA-256 produces different hashes than SHA-1. Existing CloudWatch rules will be orphaned on redeployment. New rules are created with SHA-256 names. Old rules must be cleaned up manually or via `zappa unschedule`.

2. **Python version gate:** Any deployment environment running Python 3.6-3.9 will fail at import time with a `RuntimeError`. This is intentional -- those Python versions are EOL and no longer supported by AWS Lambda.

3. **Werkzeug version jump:** Going from 0.16.1 to 3.0.6+ is a major jump. However, the only Werkzeug API Zappa uses in production code (`Response`, `ClosingIterator`) is stable across all versions. The one breaking import (`urls.url_unquote`) has been replaced with stdlib.

### Rollback Plan

All changes are isolated on branch `enhancements/snyk_vulnerability_fixes/02/DATA-1431`. If issues arise post-merge:

- **Full rollback:** Revert the merge commit on `master`.
- **Partial rollback:** Individual commits are self-contained and can be cherry-picked or reverted independently.
- **SHA-256 side effect:** The only change with external state impact. Reverting would create a second set of orphaned rules (the SHA-256 ones). Prefer cleaning up old rules instead.

---

*For the full CVE cross-reference and implementation-level details, see `SNYK_REMEDIATION_PLAN.md`.*
