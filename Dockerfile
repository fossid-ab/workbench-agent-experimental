# Use a base image with Python and development tools
FROM python:3.13-slim

# Set the working directory
WORKDIR /app

# Copy the files required for installation
COPY pyproject.toml .
COPY src/ ./src/

RUN pip install . --no-cache-dir

ENTRYPOINT [ "workbench-agent" ]