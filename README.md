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

### Продакшн через Nginx и Let's Encrypt

1. Установите `nginx` и `certbot`.
2. Разместите [nginx.conf](nginx.conf) и скорректируйте пути к сертификатам.
3. Получите сертификат:
   ```bash
   certbot certonly --standalone -d spfpsfr.online
   ```
4. Настройте автообновление: `echo "0 0 * * 0 certbot renew --post-hook 'systemctl reload nginx'" >/etc/cron.d/certbot`.
5. Запустите `python3 messenger_ws.py` (он слушает только `127.0.0.1:8765`).
6. Nginx проксирует внешний `wss://spfpsfr.online/assets/chat/socket` к внутреннему `ws://127.0.0.1:8765` и включает заголовки безопасности и лимиты.

## Подключение клиента

В другой вкладке:

```bash
npm run dev
# открыть http://127.0.0.1:8081/
```

В разделе **Settings** укажите `WS URL` сервера (по умолчанию `wss://spfpsfr.online/assets/chat/socket` или адрес вашего сервера). При недоступности WebSocket клиент попытается подключиться через SSE по `https://<host>/stream`.

## Первое сообщение

1. Откройте две вкладки `http://127.0.0.1:8081/`.
2. На вкладке **Identity** в каждой вкладке нажмите «Сгенерировать ключи».
3. Скопируйте DID из первой вкладки и добавьте во вторую через **Contacts → Add by DID**, подтвердите запрос дружбы.
4. Повторите шаг для обратной стороны.
5. Перейдите на вкладку **Chat**, выберите контакт и отправьте сообщение.

WebSocket сервер слушает порт из `.env` (по умолчанию 8765). SQLite база хранится в `im.db` или пути из `DB_PATH`.

