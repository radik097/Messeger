# Messenger

Минимальная сборка и запуск P2P-мессенджера.

## Локальный запуск

```bash
cp .env.example .env
pip install -r requirements.txt
npm install
npm run build
# при локальном запуске можно сменить DB_PATH на im.db
python3 messenger_ws.py
```

В другой вкладке:

```bash
npm run dev
# открыть http://127.0.0.1:8081/
```

## Docker

```bash
cp .env.example .env
# для Docker измените DB_PATH на /data/im.db
npm install
npm run build
docker compose up --build
```

WebSocket сервер слушает порт из `.env` (по умолчанию 8765). SQLite база хранится в `im.db` или пути из `DB_PATH`.
