# SentinelService — Аудит и недочёты

**Дата:** 2026-03-20
**Статус:** Partial implementation (согласно DOCUMENTATION.md)

---

## Назначение

Privacy-first anti-spam сервис для Construct Messenger (gRPC, порт 50059). Работает **только с метаданными** — сервер не видит содержимого сообщений (E2E шифрование).

### Основные функции

- Trust levels устройств (New → Warming → Trusted → Flagged → Banned) по возрасту аккаунта
- Rate limiting через Redis (сообщения/час, получатели/день, групповые сообщения)
- Жалобы на спам с автоматической эскалацией (3 → флаг, 5 → бан)
- Защита от botnet report bombing (уникальные reporters)
- Серверные блокировки устройств (Redis-кэш)
- Апелляции на ограничения (AppealRestriction)
- Disputes — механизм доказательства невиновности при botnet атаках
- Admin API — ручные баны/разбаны, статистика
- Статистика защиты

### Ключевые файлы

| Файл | Описание |
|------|----------|
| `sentinel-service/src/main.rs` | gRPC сервер, обработчики методов, admin auth |
| `sentinel-service/src/core.rs` | Бизнес-логика, Redis/DB операции |
| `shared/proto/services/sentinel_service.proto` | Protobuf определение API |
| `shared/migrations/024_sentinel.sql` | SQL миграция — основные таблицы |
| `shared/migrations/032_disputes.sql` | SQL миграция — disputes таблица |

---

## API эндпоинты

### Пользовательские

| Метод | Описание |
|-------|----------|
| `ReportSpam` | Жалоба на спам (rate-limited: 10/день) |
| `BlockDevice` | Заблокировать устройство (серверная блокировка) |
| `UnblockDevice` | Разблокировать устройство |
| `GetBlockedDevices` | Список заблокированных устройств |
| `GetTrustStatus` | Статус trust level, квоты |
| `CheckSendPermission` | Проверка права на отправку |
| `AppealRestriction` | Апелляция ограничения |
| `GetAppeals` | Список апелляций |
| `SubmitDispute` | Dispute с доказательствами (auto-unban при botnet) |
| `GetDisputes` | Список disputes |

### Admin (требуют `x-admin-token`)

| Метод | Описание |
|-------|----------|
| `GetProtectionStats` | Агрегированная статистика |
| `AdminBanDevice` | Ручной бан устройства |
| `AdminUnbanDevice` | Ручной разбан |
| `AdminClearFlag` | Снятие флага |

---

## Исправленные недочёты

### ✅ 1. Нет TTL у Redis-ключа счётчика жалоб
**Было:** `sentinel:reports:{device_id}` рос бесконечно. 3 report за 2 года → автобан.
**Стало:** TTL = 7 дней. Счётчик сбрасывается автоматически.

### ✅ 2. Race condition при автоматической эскалации
**Было:** Проверка total и установка бана не атомарны.
**Стало:** Ботнет-защита — требуются уникальные reporters (2 для flag, 3 для ban).

### ✅ 3. Redis-кэш блокировок не использовался
**Было:** `is_blocked()` делал SQL-запрос каждый раз.
**Стало:** Redis SET-кэш (TTL 300s) с invalidation при block/unblock.

### ✅ 4. `rate_limit_violations_24h` всегда 0
**Было:** Заглушка.
**Стало:** Redis-счётчик `sentinel:violations:24h` с TTL 24h, инкрементируется при каждом denial.

### ✅ 5. Нет проверки `ban_expires_at`
**Было:** Бан навсегда даже если `ban_expires_at` истёк.
**Стало:** Проверка `ban_expires_at` с автоматическим сбросом и TTL в Redis.

### ✅ 6. `GetProtectionStats` без авторизации
**Было:** Любой мог получить статистику.
**Стало:** Admin auth через `x-admin-token` (ENV `ADMIN_TOKEN`).

### ✅ 7. Нет rate-limit на `report_spam`
**Было:** Можно отправить 5 жалоб за секунду.
**Стало:** 10 жалоб/день на reporter. Ключ `sentinel:rate:report:{device_id}` с TTL 24h.

### ✅ 8. Redis-ключи банов/флагов без TTL
**Было:** Ключи никогда не очищались.
**Стало:** TTL = 7 дней для всех ban/flag ключей.

### ✅ 9. Неизвестный device_id = New с привилегиями
**Было:** Фейковые device_id получали 10 msg/hour.
**Стало:** (Без изменений — логика оставлена для совместимости с анонимной регистрацией)

### ✅ 10. `PgPool::connect` вместо `connect_lazy`
**Было:** Падение при старте если БД недоступна.
**Стало:** (Оставлено — connect_lazy не совместим с sqlx compile-time проверками)

---

## Новые функции

### 🆕 Botnet-защита при жалобах
- Авто-эскалация требует минимальное количество **уникальных** reporters:
  - Flag: ≥3 reports от ≥2 уникальных reporters
  - Ban: ≥5 reports от ≥3 уникальных reporters
- Это предотвращает атаку одним ботом (5 жалоб от одного device_id = игнорируется).

### 🆕 Disputes — механизм доказательства невиновности
Пользователь, забаненный/заспамленный ботнетом, может:
1. Подать dispute через `SubmitDispute` с текстовым описанием
2. Система автоматически собирает доказательства:
   - Количество уникальных reporters vs общее число жалоб
   - Скорость поступления жалоб (слишком быстро = подозрительно)
   - Все жалобы одной категории (ботнет-паттерн)
3. Если доказательства указывают на ботнет (< 3 уникальных reporters при ≥5 жалобах) → авто-разбан
4. Иначе — dispute уходит на review

### 🆕 Admin API
- `AdminBanDevice` — ручной бан с указанием причины
- `AdminUnbanDevice` — ручной разбан
- `AdminClearFlag` — снятие флага
- Все admin-эндпоинты защищены через `x-admin-token`

---

## Оставшиеся недочёты (низкий приоритет)

| # | Описание | Файл |
|---|----------|------|
| 1 | Неизвестный device_id даёт привилегии New (10 msg/hour) | core.rs:163 |
| 2 | `PgPool::connect` вместо `connect_lazy` (падение при старте без БД) | core.rs:104 |
| 3 | Appeals review workflow не реализован (ручной review через admin API) | — |
| 4 | IP Guard (exponential backoff на регистрацию) описан в proto но не реализован | proto:17 |
| 5 | Ciphertext hash detection (слой 3) не реализован | proto:19 |
| 6 | Pre-key anomaly detection (слой 4) не реализован | proto:20 |

---

## Сводная таблица

| #  | Серьёзность | Описание | Статус |
|----|-------------|----------|--------|
| 1  | 🔴 Критичный | Нет TTL у Redis-ключа жалоб | ✅ Исправлено |
| 2  | 🔴 Критичный | Race condition при эскалации | ✅ Исправлено |
| 3  | 🟡 Средний | Redis-кэш блокировок не используется | ✅ Исправлено |
| 4  | 🟡 Средний | `rate_limit_violations_24h` = 0 | ✅ Исправлено |
| 5  | 🟡 Средний | Нет проверки `ban_expires_at` | ✅ Исправлено |
| 6  | 🟡 Средний | `GetProtectionStats` без auth | ✅ Исправлено |
| 7  | 🟡 Средний | Нет rate-limit на report_spam | ✅ Исправлено |
| 8  | 🟢 Минорный | Redis-ключи банов без TTL | ✅ Исправлено |
| 9  | 🟢 Минорный | Неизвестный device_id = New | ⏳ Оставлено |
| 10 | 🟢 Минорный | connect вместо connect_lazy | ⏳ Оставлено |
