# Construct Messenger — Server Implementation Requirements

**Версия:** 2026-03-03 (обновлено)  
**Кому:** Backend-разработчик  
**Контекст:** iOS/macOS клиент готов со своей стороны. Ниже — что нужно реализовать на сервере для полной работоспособности.

Все RPC уже задекларированы в `.proto` файлах. Задача сервера — реализовать логику.

---

## Статус клиентской части (что уже реализовано на клиенте)

| Фича | Статус на клиенте |
|------|-------------------|
| Отправка `DeliveryReceipt` после расшифровки | ✅ Отправляет `DirectReceipt(DELIVERED)` через stream |
| Получение `DeliveryReceipt` от сервера | ✅ Обновляет статус сообщения в UI → зелёный кружок |
| Регистрация APNs токена | ✅ При каждом запуске |
| OTPK: загрузка 100 ключей при регистрации | ✅ |
| OTPK: пополнение если < 20 ключей | ✅ Автоматически после initSession |
| OTPK: использование при init сессии (4-DH X3DH) | ✅ Полный Signal Protocol |
| Signed prekey rotation | ✅ Клиент умеет, сервер должен хранить grace period |
| Session healing (без END_SESSION) | ✅ Автоматическое восстановление |
| Persistent ACK | ✅ CoreData, переживает рестарт |

---

## 1. Push-уведомления (APNs)

### 1.1 Что нужно

Клиент регистрирует APNs-токен при каждом запуске. Сервер должен отправлять silent push когда получатель оффлайн.

### 1.2 Регистрация токена

**RPC:** `NotificationService.RegisterDeviceToken`  
**Proto:** `services/notification_service.proto`

```protobuf
// Клиент вызывает при получении APNs токена от iOS
rpc RegisterDeviceToken(RegisterDeviceTokenRequest) returns (RegisterDeviceTokenResponse)

message RegisterDeviceTokenRequest {
  string device_token = 1;   // APNs hex token
  string device_id = 4;       // стабильный ID из Keychain (для upsert — не создаёт дубликаты)
  PushProvider provider = 5;  // PUSH_PROVIDER_APNS
  PushEnvironment environment = 6; // PUSH_ENV_SANDBOX или PUSH_ENV_PRODUCTION
  NotificationFilter notification_filter = 3; // NOTIFICATION_FILTER_SILENT
}
```

**Логика сервера:**
```sql
INSERT INTO device_push_tokens (user_id, device_id, token, provider, env, updated_at)
VALUES (...)
ON CONFLICT (device_id) DO UPDATE SET token = excluded.token, updated_at = now();
```

**Также есть старый RPC в AuthService:**
```protobuf
rpc UpdatePushToken(UpdatePushTokenRequest) returns (UpdatePushTokenResponse)
```
Оба должны писать в одну и ту же таблицу токенов. Это одна и та же операция, задублированная в двух сервисах.

### 1.3 Отправка уведомления при доставке сообщения

**Когда:** сервер принял сообщение и получатель **не подключён** к MessageStream.

**RPC:** `NotificationService.SendBlindNotification`

```protobuf
message SendBlindNotificationRequest {
  string user_id = 1;           // получатель
  optional int32 badge_count = 2; // можно не считать пока — передавать 1
  optional string activity_type = 3; // "new_message"
}
```

**Логика:**
1. Принять `SendMessageRequest`
2. Если получатель не подключён к `MessageStream` → найти все его APNs токены из таблицы
3. Отправить silent push через APNs gateway:

```json
{
  "aps": {
    "content-available": 1,
    "badge": 1
  }
}
```

> **Важно:** Payload пустой — ни имени отправителя, ни текста. Клиент сам подтянет сообщение по стриму после пробуждения. Это privacy-preserving подход (как у Signal).

**APNs endpoint:**
- Sandbox: `https://api.sandbox.push.apple.com`
- Production: `https://api.push.apple.com`
- Auth: JWT с APNs ключом (p8 файл) или сертификат

---

## 2. Delivery ACK — подтверждение расшифровки

### 2.1 Концепция

Текущая схема статусов на клиенте: `sending → sent → delivered`.

Нужно добавить: **клиент отправляет receipt после успешной расшифровки** → сервер релеит его отправителю → у отправителя статус сообщения становится `delivered`.

Это означает: ✓ = сообщение дошло И расшифровано. Никаких деталей о прочтении.

### 2.2 Уже есть в proto

**Proto:** `signaling/presence.proto` → `DeliveryReceipt`, `DirectReceipt`, `ReceiptStatus`

```protobuf
// Получатель отправляет через MessageStreamRequest
oneof request {
  DeliveryReceipt receipt = 2;  // ← уже есть
}

message DirectReceipt {
  repeated string message_ids = 1;  // batch — несколько ID за раз
  ReceiptStatus status = 2;         // RECEIPT_STATUS_DELIVERED = 1
  int64 timestamp = 3;
}
```

**Текущие статусы:**
```protobuf
enum ReceiptStatus {
  RECEIPT_STATUS_UNSPECIFIED = 0;
  RECEIPT_STATUS_DELIVERED = 1;  // ← используем это
  RECEIPT_STATUS_READ = 2;
}
```

### 2.3 Что нужно добавить в proto

Добавить новый статус `RECEIPT_STATUS_DECRYPTED`:

```protobuf
enum ReceiptStatus {
  RECEIPT_STATUS_UNSPECIFIED = 0;
  RECEIPT_STATUS_DELIVERED = 1;    // устройство получило
  RECEIPT_STATUS_READ = 2;         // пользователь открыл чат
  RECEIPT_STATUS_DECRYPTED = 3;    // NEW: расшифровано успешно
}
```

Можно и без этого — использовать `DELIVERED` как "получено и расшифровано". Зависит от желаемой семантики.

### 2.4 Поток данных

```
Получатель                    Сервер                    Отправитель
    │                            │                            │
    │ ← stream (message)         │                            │
    │ decrypt OK                 │                            │
    │ → stream (receipt          │                            │
    │    DELIVERED,              │                            │
    │    [message_id])   ────────►                            │
    │                            │ найти соединение           │
    │                            │ отправителя                │
    │                            ├──────────── receipt ──────►│
    │                            │            (stream)        │
    │                            │                            │ UI: ✓✓
```

### 2.5 Логика сервера

```
Получить MessageStreamRequest.receipt от пользователя X:
  1. Для каждого message_id:
     a. Найти отправителя (из таблицы messages)
     b. Если отправитель онлайн → отправить DeliveryReceipt в его stream
     c. Если оффлайн → сохранить receipt в очередь (pending_receipts)
        При следующем подключении отправителя → слить pending_receipts
  2. Обновить статус message в БД: status = DELIVERED
```

### 2.6 Что клиент делает (уже реализовано)

- **Клиент ОТПРАВЛЯЕТ** `DirectReceipt(DELIVERED)` через stream сразу после успешной расшифровки
- **Клиент ПОЛУЧАЕТ** `DeliveryReceipt` от сервера и обновляет статус сообщения на `.delivered`
- UI: кружок `⚪ sending → ⚫ sent → 🟢 delivered`

**Всё что нужно от сервера** — релеить receipt от получателя к отправителю (пункт 3 чеклиста).

---

## 3. Управление prekey-ами

> **Важно:** Отдельного gRPC канала не нужно. Всё на том же канале, через существующий `KeyService`.

### 3.1 Как это работает

Каждый раз когда Б инициирует сессию с А, сервер «тратит» один signed prekey А. Если prekeys закончатся — новые сессии нельзя установить.

Клиент должен периодически пополнять prekeys. Для этого нужен endpoint который скажет «сколько осталось».

### 3.2 GetPreKeyCount

**RPC:** `KeyService.GetPreKeyCount`  
**Proto:** `services/key_service.proto`

```protobuf
rpc GetPreKeyCount(GetPreKeyCountRequest) returns (GetPreKeyCountResponse)

message GetPreKeyCountResponse {
  uint32 count = 1;               // сколько prekeys сейчас на сервере
  uint32 recommended_minimum = 2; // рекомендуемый минимум (вернуть 5)
  int64 last_upload_at = 3;       // когда последний раз загружали
}
```

**Логика сервера:** просто SELECT COUNT(*) по prekeys данного device_id.

### 3.3 UploadPreKeys

**RPC:** `KeyService.UploadPreKeys`  
**Proto:** `services/key_service.proto`

```protobuf
message UploadPreKeysResponse {
  bool success = 1;
  uint32 pre_key_count = 2;  // сколько prekeys теперь на сервере (после загрузки)
  int64 uploaded_at = 3;
}
```

Клиент вызывает когда `prekey_count < 5`. Добавить в ответ реальное количество оставшихся ключей.

### 3.4 GetPreKeyBundle — поведение при «тратe» ключа

Важный нюанс: мы реализовали **полный Signal Protocol (4-DH X3DH)** с one-time prekeys.

При `GetPreKeyBundle`:
- Сервер возвращает текущий `signed_pre_key` + `identity_key`
- **Signed prekey не удалять** — используется многократно
- **One-time prekeys** (`one_time_pre_key`) — если есть, вернуть один и **удалить** (burn-after-use). Если нет — вернуть без него (клиент справляется через 3-DH fallback)
- `OneTimePreKey.key_id` должен быть включён в ответ — клиент использует его в wire format

**Proto поле:** `GetPreKeyBundleResponse.one_time_pre_key` уже есть. Добавить `one_time_pre_key_id` если нет.

### 3.5 UploadPreKeys — хранение one-time prekeys

Клиент загружает пакет one-time prekeys при регистрации (100 ключей) и автоматически пополняет когда остаётся < 20 (пакет 50 ключей).

```protobuf
message PreKeyPair {
  uint32 pre_key_id = 1;    // уникальный ID (≥ 1,000,000 чтобы не конфликтовать со signed prekeys)
  bytes pre_key_public = 2; // 32 байта (X25519 public key)
}
```

**Логика сервера:**
```sql
-- Хранить отдельно от signed prekeys
CREATE TABLE one_time_prekeys (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  key_id BIGINT NOT NULL,
  pre_key_public BYTEA NOT NULL,
  created_at TIMESTAMP DEFAULT now(),
  UNIQUE (device_id, key_id)
);

-- При UploadPreKeys: INSERT OR IGNORE (не перезаписывать существующие)
-- При GetPreKeyBundle: SELECT + DELETE один ключ атомарно
DELETE FROM one_time_prekeys
WHERE id = (
  SELECT id FROM one_time_prekeys
  WHERE device_id = $1
  ORDER BY created_at ASC
  LIMIT 1
  FOR UPDATE SKIP LOCKED
)
RETURNING key_id, pre_key_public;
```

### 3.6 GetPreKeyCount — считать one-time prekeys отдельно

`GetPreKeyCount` должен возвращать количество **one-time prekeys** (не signed prekey):

```sql
SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1;
```

Клиент вызывает этот endpoint при каждом запуске и после каждого `initReceivingSession` для определения нужно ли пополнять.

### 3.7 RotateSignedPreKey — grace period

**RPC:** `KeyService.RotateSignedPreKey`

Когда клиент загружает новый signed prekey:
- **Хранить старый signed prekey 48 часов** в таблице `old_signed_prekeys`
- `GetPreKeyBundle` возвращает НОВЫЙ ключ
- Но если получатель не смог расшифровать с новым — он попробует старые (это реализовано в Rust-ядре)

```sql
-- При RotateSignedPreKey:
INSERT INTO old_signed_prekeys (user_id, device_id, key_data, expired_at)
  SELECT user_id, device_id, signed_pre_key, now() + interval '48 hours'
  FROM devices WHERE device_id = $1;

UPDATE devices SET signed_pre_key = $new_key WHERE device_id = $1;

-- Cleanup job (раз в час):
DELETE FROM old_signed_prekeys WHERE expired_at < now();
```

---

## 4. Корректная доставка END_SESSION

### 4.1 Проблема

`END_SESSION` — это контрольное сообщение (content_type = SESSION_RESET). Оно критично для восстановления сессии. Если получатель оффлайн — оно должно лежать в очереди и быть доставлено при следующем подключении.

### 4.2 Требование

`END_SESSION` (`Envelope.content_type = SESSION_RESET`) должен:
1. Храниться в `pending_messages` как обычное сообщение
2. Доставляться через `GetPendingMessages` при следующем подключении
3. **Не терять** при истечении TTL (или иметь больший TTL, например 7 дней)
4. Если получатель оффлайн — тригернуть APNs push (важно, чтобы клиент проснулся и получил END_SESSION)

Это уже должно работать если pending_messages обрабатываются равномерно. Убедиться что SESSION_RESET не пропускается.

---

## 5. Доставка GetPendingMessages при reconnect

### 5.1 Текущая схема (уже работает частично)

Клиент при каждом reconnect вызывает `GetPendingMessages(since_cursor)` и получает все непрочитанные сообщения.

### 5.2 Что нужно проверить

- Cursor должен быть **стабильным** — при повторном запросе с тем же cursor возвращать те же сообщения
- Сообщения должны возвращаться **отсортированными по message_number ascending** (клиент применяет их по порядку)
- После успешной доставки через стрим — помечать как доставленные, но **не удалять** сразу (клиент подтвердит через `DeliveryReceipt`)
- Максимальное время хранения pending messages: **30 дней** (после этого удалять)

---

## 6. Краткий чеклист для сервера

| # | Задача | RPC / Proto | Приоритет |
|---|--------|-------------|-----------|
| 1 | Хранить APNs токены (upsert by device_id) | `NotificationService.RegisterDeviceToken` + `AuthService.UpdatePushToken` | 🔴 Высокий |
| 2 | Отправлять silent APNs push при оффлайн-доставке | `NotificationService.SendBlindNotification` | 🔴 Высокий |
| 3 | Релеить `DeliveryReceipt` от получателя к отправителю через stream | `MessageStream` `receipt` field | 🔴 Высокий |
| 4 | Хранить one-time prekeys в отдельной таблице | `KeyService.UploadPreKeys` | 🔴 Высокий |
| 5 | `GetPreKeyBundle`: вернуть + удалить один OTPK (если есть) | `KeyService.GetPreKeyBundle` | 🔴 Высокий |
| 6 | `GetPreKeyCount`: считать кол-во one-time prekeys | `KeyService.GetPreKeyCount` | 🔴 Высокий |
| 7 | Сохранять pending receipts для оффлайн-отправителей | новая таблица `pending_receipts` | 🟡 Средний |
| 8 | Вернуть реальный `pre_key_count` в `UploadPreKeysResponse` | `KeyService.UploadPreKeys` | 🟡 Средний |
| 9 | Grace period 48ч для старых signed prekeys при RotateSignedPreKey | `KeyService.RotateSignedPreKey` | 🟡 Средний |
| 10 | Гарантировать доставку SESSION_RESET через pending queue | `messaging_service.proto` | 🟡 Средний |
| 11 | Добавить `RECEIPT_STATUS_DECRYPTED = 3` в proto | `signaling/presence.proto` | 🟢 Низкий |

---

## 7. Что НЕ нужно менять на сервере

- **Wire format сообщений** — `encrypted_payload` сервер не парсит, передаёт as-is ✅
- **Proto для основного потока сообщений** — всё уже определено ✅
- **Отдельный канал для prekeys** — не нужен, используем тот же gRPC канал ✅
- **Шифрование** — сервер никогда не видит plaintext, только opaque bytes ✅
- **Логика шифрования/дешифрования** — полностью на клиенте (Rust-ядро) ✅

---

## 8. Порядок реализации (рекомендуемый)

```
Sprint 1 (критичное — без этого не работает полный Signal Protocol):
  1. Хранить one-time prekeys (таблица one_time_prekeys)
  2. GetPreKeyBundle: вернуть + сжечь один OTPK
  3. GetPreKeyCount: SELECT COUNT(*) из one_time_prekeys
  4. DeliveryReceipt relay (получатель → сервер → отправитель)

Sprint 2 (надёжность):
  5. RegisterDeviceToken → хранение APNs токенов
  6. Silent APNs push при оффлайн-доставке
  7. Реальный счётчик в UploadPreKeysResponse
  8. Pending receipts для оффлайн-отправителей

Sprint 3 (polish):
  9. Grace period 48ч для signed prekeys
  10. RECEIPT_STATUS_DECRYPTED в proto
  11. Аудит TTL для pending messages
```

