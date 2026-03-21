# SentinelService — Аудит и недочёты

**Дата:** 2026-03-20
**Статус:** Partial implementation (согласно DOCUMENTATION.md)

---

## Назначение

Privacy-first anti-spam сервис для Construct Messenger (gRPC, порт 50059). Работает **только с метаданными** — сервер не видит содержимое сообщений (E2E шифрование).

### Основные функции

- Trust levels устройств (New → Warming → Trusted → Flagged → Banned) по возрасту аккаунта
- Rate limiting через Redis (сообщения/час, получатели/день, групповые сообщения)
- Жалобы на спам с автоматической эскалацией (3 → флаг, 5 → бан)
- Серверные блокировки устройств
- Апелляции на ограничения
- Статистика защиты (admin)

### Ключевые файлы

| Файл | Описание |
|------|----------|
| `sentinel-service/src/main.rs` | gRPC сервер, обработчики методов |
| `sentinel-service/src/core.rs` | Бизнес-логика, Redis/DB операции |
| `shared/proto/services/sentinel_service.proto` | Protobuf определение API |
| `shared/migrations/024_sentinel.sql` | SQL миграция таблиц |

---

## Недочёты

### 🔴 Критичные

#### 1. Нет TTL у Redis-ключа счётчика жалоб

**Файл:** `sentinel-service/src/core.rs:338`
**Проблема:** Ключ `sentinel:reports:{device_id}` растёт бесконечно без сброса. Если device получит 3 report за 2 года — его забанят автоматически.
**Решение:** Добавить TTL к ключу или фильтровать `spam_reports` по `created_at` при подсчёте.

#### 2. Race condition при автоматической эскалации

**Файл:** `sentinel-service/src/core.rs:342-349`
**Проблема:** Проверка `total >= AUTO_BAN_REPORTS` и установка бана не атомарны. Два параллельных `report_spam` могут одновременно вызвать `set_banned`. Не критично (идемпотентно через `ON CONFLICT`), но лишние SQL/Redis запросы.
**Решение:** Использовать Redis WATCH/MULTI или Lua-скрипт для атомарной инкрементации + проверки.

---

### 🟡 Средние

#### 3. Redis-кэш блокировок описан, но не используется

**Файл:** `sentinel-service/src/core.rs:20` vs `core.rs:252-262`
**Проблема:** В комментарии указан ключ `sentinel:blocks:{blocker} → SET (TTL 300s)`, но метод `is_blocked()` делает только SQL-запрос. Каждый `CheckSendPermission` ходит в БД.
**Решение:** Реализовать Redis-кэш блокировок как описано в комментарии, с fallback на БД.

#### 4. `rate_limit_violations_24h` всегда 0

**Файл:** `sentinel-service/src/core.rs:438`
**Проблема:** Заглушка — статистика rate-limit нарушений недоступна. Комментарий "tracked in Redis; skip for now".
**Решение:** Добавить Redis-счётчик при каждом отказе в `check_send_permission` с TTL 24h.

#### 5. Нет проверки `ban_expires_at`

**Файл:** `sentinel-service/src/core.rs:142-151`, `shared/migrations/024_sentinel.sql:11`
**Проблема:** В таблице `device_flags` есть колонка `ban_expires_at` для временных банов, но код её не проверяет. Бан навсегда даже если срок истёк.
**Решение:** Добавить проверку `ban_expires_at > NOW()` в `trust_level()` и при бане в Redis ставить TTL.

#### 6. `GetProtectionStats` без авторизации

**Файл:** `sentinel-service/src/main.rs:266`
**Проблема:** TODO "add admin auth check" — любой вызывающий может получить агрегированную статистику.
**Решение:** Добавить проверку admin-роли через JWT claims или отдельный admin token.

#### 7. Нет rate-limit на `report_spam`

**Файл:** `sentinel-service/src/core.rs:318`
**Проблема:** Нет защиты от report bombing — одно устройство может отправить 5 жалоб за секунду и забанить кого угодно.
**Решение:** Добавить rate-limit на жалобы (например, 5 report/день на device) или проверку что reporter имеет хотя бы одну историю взаимодействия с reported.

---

### 🟢 Минорные

#### 8. Redis-ключи банов/флагов без TTL

**Файл:** `sentinel-service/src/core.rs:359, 376`
**Проблема:** `set_flagged` и `set_banned` ставят ключи без TTL. Если устройство разбанится вручную в БД, Redis-кэш никогда не обновится (кроме перезапуска или явной очистки).
**Решение:** Либо добавить TTL (например, 7 дней) с ре-баном при `trust_level()` fallback, либо реализовать explicit cache invalidation при разбане.

#### 9. Неизвестный device_id даёт привилегии New

**Файл:** `sentinel-service/src/core.rs:163`
**Проблема:** Если device_id не найден в БД, `trust_level()` возвращает `New` (10 msg/hour). Фейковые device_id могут спамить без регистрации.
**Решение:** Для неизвестных device_id возвращать более строгий лимит или блокировать.

#### 10. `PgPool::connect` вместо `PgPool::connect_lazy`

**Файл:** `sentinel-service/src/core.rs:104`
**Проблема:** Старт сервиса упадёт если БД/Redis недоступны. Нет retry/backoff при инициализации.
**Решение:** Использовать `PgPool::connect_lazy()` или добавить retry с backoff.

---

## Сводная таблица

| #  | Серьёзность | Описание | Файл | Строка |
|----|-------------|----------|------|--------|
| 1  | 🔴 Критичный | Нет TTL у Redis-ключа жалоб | core.rs | 338 |
| 2  | 🔴 Критичный | Race condition при эскалации | core.rs | 342-349 |
| 3  | 🟡 Средний | Redis-кэш блокировок не используется | core.rs | 252-262 |
| 4  | 🟡 Средний | `rate_limit_violations_24h` = 0 | core.rs | 438 |
| 5  | 🟡 Средний | Нет проверки `ban_expires_at` | core.rs | 142-151 |
| 6  | 🟡 Средний | `GetProtectionStats` без auth | main.rs | 266 |
| 7  | 🟡 Средний | Нет rate-limit на report_spam | core.rs | 318 |
| 8  | 🟢 Минорный | Redis-ключи банов без TTL | core.rs | 359, 376 |
| 9  | 🟢 Минорный | Неизвестный device_id = New | core.rs | 163 |
| 10 | 🟢 Минорный | connect вместо connect_lazy | core.rs | 104 |
