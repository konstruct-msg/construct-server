#!/usr/bin/env bash
#
# Проверка восстановления. Запускается НА МАШИНЕ ОПЕРАТОРА, не на сервере:
# для расшифровки нужен приватный age-ключ, а он на сервере лежать не должен.
#
# Смысл в том, что бэкап — это не файл, а процедура. Непроверенная процедура
# это гипотеза, и проверять её во время аварии поздно. Скрипт берёт последнюю
# копию из Storage Box, поднимает одноразовый Postgres, разворачивает дамп и
# сверяет то, что должно быть непусто. Затем всё сносит.
#
#   ./ops/restore-test.sh                 # последняя daily
#   ./ops/restore-test.sh 20260813T140000Z
#
# Переменные — те же ops/backup.env, плюс:
#   BACKUP_AGE_IDENTITY   путь к приватному ключу (~/.config/age/construct-backup.key)
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
set -a; . ./ops/backup.env; set +a
: "${BACKUP_AGE_IDENTITY:?путь к приватному ключу}" "${BACKUP_SSH_HOST:?}" "${BACKUP_SSH_USER:?}"
BACKUP_SSH_PORT="${BACKUP_SSH_PORT:-23}"
REMOTE="$BACKUP_SSH_USER@$BACKUP_SSH_HOST"
SSH_OPTS=(-p "$BACKUP_SSH_PORT" -o BatchMode=yes)

STAMP="${1:-}"
if [ -z "$STAMP" ]; then
  STAMP=$(ssh "${SSH_OPTS[@]}" "$REMOTE" "ls -1 $BACKUP_REMOTE_DIR/daily | sort | tail -1" | tr -d '\r/')
fi
[ -n "$STAMP" ] || { echo "в $BACKUP_REMOTE_DIR/daily пусто — бэкапов НЕТ"; exit 1; }
echo "проверяем копию $STAMP"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"; docker rm -f construct-restore-test >/dev/null 2>&1 || true' EXIT
scp "${SSH_OPTS[@]}" -q "$REMOTE:$BACKUP_REMOTE_DIR/daily/$STAMP/pg-*.sql.gz.age" "$WORK/"
age -d -i "$BACKUP_AGE_IDENTITY" "$WORK"/pg-*.sql.gz.age | gunzip > "$WORK/dump.sql"
echo "дамп расшифрован: $(wc -l < "$WORK/dump.sql") строк SQL"

docker run -d --rm --name construct-restore-test \
  -e POSTGRES_PASSWORD=restoretest -e POSTGRES_USER=construct -e POSTGRES_DB=construct \
  postgres:16-alpine >/dev/null
for _ in $(seq 1 40); do
  docker exec construct-restore-test pg_isready -U construct >/dev/null 2>&1 && break
  sleep 1
done

# Ошибки восстановления не глотаем. Дамп с --clean на пустую базу выдаёт
# безобидные NOTICE про несуществующие объекты; всё остальное — повод смотреть.
docker exec -i construct-restore-test psql -U construct -d construct -v ON_ERROR_STOP=0 \
  < "$WORK/dump.sql" 2>&1 | grep -E "^ERROR" | grep -v "does not exist" > "$WORK/errors.txt" || true
if [ -s "$WORK/errors.txt" ]; then
  echo "ОШИБКИ при восстановлении:"; head -20 "$WORK/errors.txt"; exit 1
fi

echo "== что восстановилось =="
docker exec construct-restore-test psql -U construct -d construct -tAc "
SELECT 'users=' || (SELECT count(*) FROM users)
    || ' devices=' || (SELECT count(*) FROM devices)
    || ' kt_leaves=' || (SELECT count(*) FROM kt_leaves)
    || ' media_files=' || (SELECT count(*) FROM media_files)"

# Ноль строк в users — успешное восстановление пустоты. Это выглядит как
# «всё прошло» и является худшим возможным исходом, поэтому проверяется явно.
COUNT=$(docker exec construct-restore-test psql -U construct -d construct -tAc "SELECT count(*) FROM users")
[ "$COUNT" -gt 0 ] || { echo "ПРОВАЛ: users пуст — копия бесполезна"; exit 1; }
echo "восстановление проверено: $COUNT пользователей"
