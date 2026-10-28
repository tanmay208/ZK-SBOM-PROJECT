FROM python:3.11-slim

RUN apt-get update && apt-get install -y nodejs curl tar gzip libc++1 && rm -rf /var/lib/apt/lists/*
RUN curl -sL https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/cpp/installation/install | bash
RUN /root/.bb/bbup -v 0.46.1

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
EXPOSE 8004

CMD ["uvicorn", "verification_service.app.main:app", "--host", "0.0.0.0", "--port", "8004"]
