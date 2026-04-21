FROM public.ecr.aws/docker/library/python:3.12-slim
ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt --no-cache-dir
COPY code/ code/
RUN useradd -m ai-intel
RUN chown -R ai-intel:ai-intel /app
USER ai-intel
EXPOSE 8000
CMD ["uvicorn", "code.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
