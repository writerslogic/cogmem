# Reproducible image for the cogmem MCP server (stdio JSON-RPC).
#
# Ships the verifiable-memory tools — did:key identity, W3C VC verification, the
# hash-chained transparency log, Merkle tree head, and inclusion receipts — which
# need only cryptography + cbor2. Semantic recall needs the warm daemon and
# fastembed (heavy and stateful), so it is intentionally NOT in this image; the
# `recall` tool fails open (returns no memories) when the daemon is absent.
#
#   docker build -t cogmem-mcp .
#   docker run -i --rm cogmem-mcp        # speaks MCP over stdio
FROM python:3.12-slim

# A venv keeps the install self-contained and sidesteps PEP 668 (the slim image's
# system Python is externally managed and rejects --system installs).
ENV VENV=/app/.venv \
    PATH=/app/.venv/bin:$PATH \
    COGMEM_HOME=/app \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN python3 -m venv "$VENV" && pip install --no-cache-dir --upgrade pip

# Sources needed to build and install the package. Core deps only (cryptography +
# cbor2 from pyproject); the recall extra (fastembed) is intentionally omitted. The
# vault (identity key, credentials, log) is created at runtime under COGMEM_HOME=/app.
COPY pyproject.toml README.md ./
COPY engine/ /app/engine/
RUN pip install --no-cache-dir .

# Run unprivileged; the vault lives under /app, which the runtime user owns.
RUN useradd -u 10001 -m cogmem && mkdir -p /app/vault && chown -R cogmem:cogmem /app
USER cogmem

# stdio MCP transport: newline-delimited JSON-RPC on stdin/stdout (the `cogmem`
# console script delegates `mcp` to the server).
CMD ["cogmem", "mcp"]
