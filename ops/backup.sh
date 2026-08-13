#!/usr/bin/env bash
#
# Резервное копирование construct-server на Hetzner Storage Box.
#
# Что и почему:
#
#   Postgres  — единственное невосстановимое. Журнал Key Transparency
#               append-only и не может быть пересобран, привязки аккаунтов к
#               устройствам тоже. 24 МБ.
#   Redis     — офлайн-очереди: принятые от отправителя и ещё не доставленные
#               сообщения. Потеря = молча пропавшие сообщения, ровно то, ради
#               чего выбран noeviction. 30 МБ.
#   Медиа НЕ копируются намеренно: срок жизни 7 дней, содержимое зашифровано
#               клиентом, отправитель держит свою копию. Копировать то, что
#               через неделю удалится само, — платить за иллюзию полноты.
#
# Шифрование до отправки, а не «шифрование у провайдера». Дамп не содержит
# текстов сообщений (E2EE), но содержит социальный граф: user_blocks,
# contact_links, group_members, плюс хеши имён и recovery-бандлы. Hetzner
# получает шифротекст и ничего больше.
#
# ПРИВАТНЫЙ КЛЮЧ НЕ ДОЛЖЕН ЛЕЖАТЬ НА ЭТОМ СЕРВЕРЕ. Иначе потеря машины уносит
# данные и ключ одновременно, и бэкап оказывается декоративным. Здесь только
# публичный ключ получателя (age умеет шифровать, не умея расшифровать).
#
# Установка описана в construct-docs manuals&instructions/Backups.md
#
# Переменные (ops/backup.env, chmod 600):
#   BACKUP_AGE_RECIPIENT   age1... — публичный ключ, приватный хранится вне сервера
#   BACKUP_SSH_HOST        uXXXXXX.your-storagebox.de
#   BACKUP_SSH_USER        uXXXXXX
#   BACKUP_SSH_PORT        23           (Hetzner: 23 для SSH/SFTP, не 22)
#   BACKUP_REMOTE_DIR      construct    (каталог внутри Storage Box)
#   BACKUP_KEEP_DAILY      7
#   BACKUP_KEEP_WEEKLY     4
set -euo pipefail

cd "$(dirname "$0")/.."
ENV_FILE="ops/backup.env"
[ -f "$ENV_FILE" ] || { echo "нет $ENV_FILE — см. заголовок скрипта"; exit 2; }
# shellcheck disable=SC1090
set -a; . "./$ENV_FILE"; set +a

: "${BACKUP_AGE_RECIPIENT:?}"
if [ "${1:-}" != "--local-only" ]; then
  : "${BACKUP_SSH_HOST:?}" "${BACKUP_SSH_USER:?}" "${BACKUP_REMOTE_DIR:?}"
fi
BACKUP_SSH_PORT="${BACKUP_SSH_PORT:-23}"
BACKUP_KEEP_DAILY="${BACKUP_KEEP_DAILY:-7}"
BACKUP_KEEP_WEEKLY="${BACKUP_KEEP_WEEKLY:-4}"

# --local-only: всё, кроме выгрузки. Существует, чтобы конвейер (дамп →
# gzip → age → проверка размера) можно было прогнать до того, как заведено
# внешнее хранилище, и чтобы отделять «сломался дамп» от «не достучались до
# Storage Box» при разборе падения.
LOCAL_ONLY=0
[ "${1:-}" = "--local-only" ] && LOCAL_ONLY=1

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

# ── Postgres ────────────────────────────────────────────────────────────────
# --clean --if-exists, чтобы восстановление на непустую базу не требовало
# ручного удаления. Пайп с `set -o pipefail` — иначе падение pg_dump
# замаскируется успешным age и уедет пустой файл.
log "pg_dump"
docker exec construct-postgres pg_dump -U construct -d construct --clean --if-exists \
  | gzip -9 \
  | age -r "$BACKUP_AGE_RECIPIENT" -o "$WORK/pg-$STAMP.sql.gz.age"

# ── Redis ───────────────────────────────────────────────────────────────────
# BGSAVE + ожидание, а не копирование dump.rdb «как есть»: файл на диске может
# быть часовой давности, и именно эта разница однажды и есть потерянные
# сообщения. rdb_last_save_time сравнивается с временем ДО запроса.
log "redis BGSAVE"
RPW="$(grep -oP '(?<=^REDIS_PASSWORD=).*' .env)"
rcli() { docker exec construct-redis redis-cli -a "$RPW" --no-auth-warning "$@" 2>/dev/null; }
BEFORE="$(rcli lastsave | tr -d '\r')"
rcli bgsave >/dev/null
for _ in $(seq 1 60); do
  sleep 2
  NOW="$(rcli lastsave | tr -d '\r')"
  [ "$NOW" != "$BEFORE" ] && break
done
[ "${NOW:-$BEFORE}" != "$BEFORE" ] || { echo "BGSAVE не завершился за 2 минуты"; exit 1; }
docker exec construct-redis cat /data/dump.rdb \
  | gzip -9 \
  | age -r "$BACKUP_AGE_RECIPIENT" -o "$WORK/redis-$STAMP.rdb.gz.age"

# ── Проверка до отправки ────────────────────────────────────────────────────
# Пустой или обрезанный файл заливается так же успешно, как целый. Порог в
# 1 МБ выбран как заведомо ниже реального (pg ~7 МБ, redis ~10 МБ сжатыми) и
# заведомо выше пустого age-конверта.
for f in "$WORK"/*.age; do
  SIZE=$(stat -c%s "$f")
  [ "$SIZE" -gt 1048576 ] || { echo "подозрительно мал: $f ($SIZE Б)"; exit 1; }
  log "$(basename "$f") — $((SIZE / 1024)) КБ"
done

# ── Отправка ────────────────────────────────────────────────────────────────
if [ "$LOCAL_ONLY" = "1" ]; then
  BASE="${BACKUP_LOCAL_DIR:-$HOME/backups}"
  OUT="$BASE/$STAMP"
  mkdir -p "$OUT" && cp "$WORK"/*.age "$OUT/"
  # Ротация и здесь: 23 МБ в сутки без неё это 8 ГБ в год, и первым о них
  # узнает DiskFillingUp, который посоветует переносить медиа в S3.
  ( cd "$BASE" && ls -1d 2*/ 2>/dev/null | sort | head -n -"$BACKUP_KEEP_DAILY" | xargs -r rm -rf )
  log "--local-only: файлы в $OUT, выгрузка пропущена"
  # Копия на том же хосте защищает от испорченной миграции, ошибочного DELETE и
  # повреждения базы — то есть от более вероятного. От потери машины она не
  # защищает ни от чего, и пока не подключено внешнее хранилище, это надо
  # держать в голове, а не считать вопрос закрытым.
  log "ВНИМАНИЕ: копия лежит на том же сервере — потеря машины уносит и её"
  exit 0
fi

SSH_OPTS=(-p "$BACKUP_SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=yes)
REMOTE="$BACKUP_SSH_USER@$BACKUP_SSH_HOST"
DAY_DIR="$BACKUP_REMOTE_DIR/daily/$STAMP"

log "загрузка в $REMOTE:$DAY_DIR"
ssh "${SSH_OPTS[@]}" "$REMOTE" "mkdir -p $DAY_DIR"
scp "${SSH_OPTS[@]}" -q "$WORK"/*.age "$REMOTE:$DAY_DIR/"

# Проверяем размеры на той стороне: scp молчит при усечении на переполненном
# томе, и обнаруживается это при восстановлении.
LOCAL_SUM=$(cat "$WORK"/*.age | sha256sum | cut -d' ' -f1)
REMOTE_SUM=$(ssh "${SSH_OPTS[@]}" "$REMOTE" "cat $DAY_DIR/*.age | sha256sum | cut -d' ' -f1")
[ "$LOCAL_SUM" = "$REMOTE_SUM" ] || { echo "контрольные суммы разошлись"; exit 1; }
log "sha256 совпал"

# По воскресеньям — копия в weekly.
if [ "$(date -u +%u)" = "7" ]; then
  ssh "${SSH_OPTS[@]}" "$REMOTE" "mkdir -p $BACKUP_REMOTE_DIR/weekly && cp -r $DAY_DIR $BACKUP_REMOTE_DIR/weekly/"
  log "недельная копия сделана"
fi

# ── Ротация ─────────────────────────────────────────────────────────────────
# Удаляем только то, что лишнее СВЕРХ лимита, и только если сегодняшняя копия
# уже на месте (проверка выше прошла). Обратный порядок однажды оставил бы ноль
# копий в день, когда pg_dump упал.
ssh "${SSH_OPTS[@]}" "$REMOTE" "
  cd $BACKUP_REMOTE_DIR/daily 2>/dev/null && ls -1d */ 2>/dev/null | sort | head -n -$BACKUP_KEEP_DAILY | xargs -r rm -rf
  cd $BACKUP_REMOTE_DIR/weekly 2>/dev/null && ls -1d */ 2>/dev/null | sort | head -n -$BACKUP_KEEP_WEEKLY | xargs -r rm -rf
  true"

log "готово: $DAY_DIR"
