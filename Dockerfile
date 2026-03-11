FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/ scripts/
COPY web/ web/

EXPOSE 5000

CMD ["python", "web/app.py"]
