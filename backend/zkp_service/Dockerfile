FROM python:3.11-slim

# Install dependencies for Nargo and Barretenberg
RUN apt-get update && apt-get install -y curl tar gzip jq bash libstdc++6 git libc++1 libc++abi1 && \
    rm -rf /var/lib/apt/lists/*

# Install Nargo (0.32.0)
RUN curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/noirup | bash -s -- -v 0.32.0

# Install Barretenberg (bbup)
RUN curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/cpp/installation/install | bash && \
    ~/.bb/bbup -v 0.46.1

ENV PATH="/root/.nargo/bin:/root/.bb:${PATH}"

WORKDIR /app

COPY shared/requirements.txt /tmp/shared-requirements.txt
RUN pip install --no-cache-dir -r /tmp/shared-requirements.txt

COPY shared /app/shared
COPY sbom_service /app/sbom_service
COPY vulnerability_service /app/vulnerability_service
COPY policy_service /app/policy_service
COPY zkp_service /app/zkp_service
COPY verification_service /app/verification_service

ENV PYTHONPATH=/app
EXPOSE 8003

CMD ["uvicorn", "zkp_service.app.main:app", "--host", "0.0.0.0", "--port", "8003"]
