FROM cgr.dev/chainguard/python:latest-dev as builder
WORKDIR /app
COPY pyproject.toml .
RUN pip install -e . --user

FROM cgr.dev/chainguard/python:latest
WORKDIR /app
COPY --from=builder /home/nonroot/.local/lib/python3.12/site-packages /home/nonroot/.local/lib/python3.12/site-packages
COPY workbench-agent.py .
ENTRYPOINT [ "python", "/app/workbench-agent.py" ]