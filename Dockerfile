FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --force-reinstall -r requirements.txt \
    && python - <<'PY'
import fastmcp
from fastmcp.server.auth.providers.azure import AzureProvider
import fastmcp.server.tasks.routing
print("FastMCP runtime verification OK:", getattr(fastmcp, "__version__", "unknown"))
print("AzureProvider import OK:", AzureProvider.__name__)
print("Task routing import OK")
PY

COPY app.py .

# Fail the image build if app.py contains a syntax error.
RUN python -m py_compile app.py

EXPOSE 8000

CMD ["python", "app.py"]
