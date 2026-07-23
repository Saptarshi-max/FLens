# Development Guide

## Environment

- Python 3.12+
- Optional: virtual environment tool of your choice

## Install

```bash
pip install -e .[dev]
```

## Run Tests

```bash
pytest -v
pytest --cov
```

## Static Analysis

```bash
ruff check .
mypy .
```

## Run CLI

```bash
flens scan sample_data/rootfs --report-out sample_data/report.html
```

## Run API

```bash
uvicorn app.presentation.api.main:api --reload
```

## TDD Workflow Recommendation

1. Add or update a use-case-driven test first.
2. Add or update adapter tests (detector/provider/report).
3. Implement production code behind existing interface contracts.
4. Run lint/type/test gates before commit.
