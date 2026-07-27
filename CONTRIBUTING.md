# Contributing

Use Python 3.12 and `uv sync`, then run `uv run pytest`, `uv run ruff check .`, and
`uv run mypy app scripts`. Keep Clean Architecture boundaries intact and do not commit proprietary
firmware, extracted rootfs trees, credentials, or generated local output.

New version evidence, identity aliases, CPE mappings, and vulnerability matches require verifiable
evidence and regression tests. Pull requests should explain false-positive trade-offs and include
focused tests.
