# Stage 1: build the React dashboard
FROM node:20-slim AS web
WORKDIR /w
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: Python backend serving the API and the built dashboard
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 SENTINEL_PUBLIC_MODE=1 SENTINEL_DATA_DIR=/var/data
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY common/ common/
COPY saas/ saas/
COPY --from=web /w/dist web/dist
CMD ["python", "-m", "saas.main"]
