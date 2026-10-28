FROM python:3.11-slim



WORKDIR /app

# Install shared dependencies first (layer caching)
COPY shared/requirements.txt /tmp/shared-requirements.txt
RUN pip install --no-cache-dir -r /tmp/shared-requirements.txt

# Copy shared library
COPY shared /app/shared

# Copy all service code to satisfy cross-imports
COPY sbom_service /app/sbom_service
COPY vulnerability_service /app/vulnerability_service
COPY policy_service /app/policy_service
COPY zkp_service /app/zkp_service
COPY verification_service /app/verification_service
ENV PYTHONPATH=/app
EXPOSE 8000

CMD ["uvicorn", "sbom_service.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
