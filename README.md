# Messenger

Минимальная сборка и запуск P2P-мессенджера.

## Клонирование

```bash
git clone https://example.com/Messenger.git
cd Messenger
```

## Запуск сервера

### Локально

```bash
cp .env.example .env
pip install -r requirements.txt
npm install
npm run build
# при локальном запуске можно сменить DB_PATH на im.db
python3 messenger_ws.py
```

### Docker

```bash
cp .env.example .env
# для Docker измените DB_PATH на /data/im.db
npm install
npm run build
docker compose up --build
```

## Подключение клиента

В другой вкладке:

```bash
npm run dev
# открыть http://127.0.0.1:8081/
```

В разделе **Settings** укажите `WS URL` сервера (по умолчанию `ws://127.0.0.1:8765` или адрес удалённого сервера).

## Первое сообщение

1. Откройте две вкладки `http://127.0.0.1:8081/`.
2. На вкладке **Identity** в каждой вкладке нажмите «Сгенерировать ключи».
3. Скопируйте DID из первой вкладки и добавьте во вторую через **Contacts → Add by DID**, подтвердите запрос дружбы.
4. Повторите шаг для обратной стороны.
5. Перейдите на вкладку **Chat**, выберите контакт и отправьте сообщение.

WebSocket сервер слушает порт из `.env` (по умолчанию 8765). SQLite база хранится в `im.db` или пути из `DB_PATH`.

