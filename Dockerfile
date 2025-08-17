# build frontend
FROM node:20-alpine AS frontend
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY web/src ./web/src
COPY esbuild.config.mjs ./
RUN npm run build

# runtime
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY messenger_ws.py ./
COPY --from=frontend /app/web ./web
CMD ["python", "messenger_ws.py"]
