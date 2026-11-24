FROM python:3.12-slim

# Run as an unprivileged user inside the container.
RUN useradd --create-home --uid 10001 portal
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=portal:portal . .
USER portal

ENV HOST=0.0.0.0 \
    UNIPORTAL_DB=/home/portal/uniportal.db
EXPOSE 5000
CMD ["python", "app.py"]
