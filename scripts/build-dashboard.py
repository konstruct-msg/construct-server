#!/usr/bin/env python3
"""Rebuild construct-overview.json from metrics that are actually produced.

The previous dashboard was written from intent: 27 panels, of which 19 read
metrics that no code path ever records. Sixteen of the 38 metrics declared in
construct-metrics have no producer anywhere in the workspace — the panel could
not populate if the whole user base logged in at once. "No data" on a screen is
worse than a missing panel: it reads as an outage.

So this generator does the opposite. Every expression is executed against the
running Prometheus first, and a panel is written only if it returned series, or
if it is explicitly marked `idle=True` — meaning a producer exists in the code
and we are waiting for the event (calls, fail-open) rather than for the wiring.

Usage:
  python3 build_dashboard.py probe   > exprs.txt   # collect expressions
  python3 build_dashboard.py write   results.json  # generate from probe results
"""
import json
import sys
from pathlib import Path

DASH = Path("/Users/maximeliseyev/Code/construct-server/ops/grafana/dashboards/construct-overview.json")
DS = {"type": "prometheus", "uid": "construct-prometheus"}

# (row, title, [(expr, legend)], type, unit, desc, idle)
P = []


def panel(row, title, targets, kind="timeseries", unit="short", desc="", idle=False,
          w=8, h=7, thresholds=None, maxv=None):
    P.append(dict(row=row, title=title, targets=targets, kind=kind, unit=unit,
                  desc=desc, idle=idle, w=w, h=h, thresholds=thresholds, maxv=maxv))


GREEN = [{"color": "green", "value": None}]
RED_HIGH = [{"color": "green", "value": None}, {"color": "yellow", "value": 0.75},
            {"color": "red", "value": 0.9}]
RED_LOW = [{"color": "red", "value": None}, {"color": "yellow", "value": 0.10},
           {"color": "green", "value": 0.25}]

# ── ЧТО СЕЙЧАС РАБОТАЕТ ─────────────────────────────────────────────────────
R1 = "СОСТОЯНИЕ — что запущено и живо ли оно"

panel(R1, "Что запущено", [("construct_build_info", "{{service}} {{version}} {{commit}}")],
      kind="table", w=10, h=7,
      desc="Версия и коммит каждого сервиса, вживую. Это ответ на вопрос «что "
           "сейчас крутится» — раньше на него отвечали поиском по git. Разные "
           "коммиты в столбце означают частичный деплой.")

panel(R1, "Скрейпы живы", [("sum(up)", "up"), ("count(up)", "всего таргетов")],
      kind="stat", w=4, h=7, thresholds=GREEN,
      desc="Если эти два числа разошлись — часть метрик не собирается, и правила, "
           "которые их читают, вечно зелёные не от здоровья, а от отсутствия данных.")

panel(R1, "Аптайм сервисов (перезапуск = обрыв)",
      [("time() - process_start_time_seconds", "{{job}}")],
      unit="s", w=10, h=7,
      desc="Пила вместо прямой — сервис перезапустился. Единственный способ увидеть "
           "молчаливые рестарты: контейнер с restart:unless-stopped поднимается сам "
           "и в docker ps выглядит как «Up 2 minutes» без объяснений.")

R2 = "ТРАФИК — то, что делают пользователи"

panel(R2, "Сообщений в секунду", [("sum(rate(construct_messages_sent_total[5m]))", "принято сервером")],
      idle=True,
      desc="Принятых messaging-сервисом. Ноль при живых сессиях — не тишина, а "
           "проблема доставки: клиент шлёт, сервер не считает.")

panel(R2, "Задержка доставки",
      [("histogram_quantile(0.50, sum by (le) (rate(construct_message_delivery_time_seconds_bucket[5m])))", "p50"),
       ("histogram_quantile(0.95, sum by (le) (rate(construct_message_delivery_time_seconds_bucket[5m])))", "p95"),
       ("histogram_quantile(0.99, sum by (le) (rate(construct_message_delivery_time_seconds_bucket[5m])))", "p99")],
      unit="s",
      idle=True,
      desc="От приёма сервером до подтверждённой доставки. Гистограмма есть и "
           "наполняется — это единственная наша метрика качества, а не объёма.")

panel(R2, "Очередь офлайн: подрезки",
      [("sum(rate(construct_msg_offline_trim_total[5m]))", "XTRIM после ACK/с")],
      idle=True,
      desc="Очередь режется только после ACK клиента. Ноль подрезок при идущем "
           "трафике означает, что Redis растёт и не убывает — предвестник упора в "
           "maxmemory, а он с noeviction останавливает доставку.")

panel(R2, "Пуш пропущен (получатель онлайн)",
      [("sum(rate(construct_msg_push_skipped_online_total[5m]))", "пропущено/с")],
      idle=True,
      desc="Экономия APNs: получатель держит стрим, пуш не нужен. Резкий рост при "
           "неизменном трафике = клиенты перестали закрывать стримы.")

panel(R2, "Защита отправителя: токены",
      [("sum(rate(construct_stealth_token_check_total[5m]))", "проверок/с"),
       ("sum(rate(construct_stealth_token_present_total[5m]))", "с токеном/с"),
       ("sum(rate(construct_stealth_sealed_local_total[5m]))", "sealed локально/с")],
      idle=True,
      desc="Расхождение «проверок» и «с токеном» — доля отправок без privacy-pass. "
           "Именно это надо видеть перед тем, как включать enforce: включить, когда "
           "линии не сошлись, значит отрезать часть отправителей.")

panel(R2, "Ошибки аутентификации", [("sum by (reason) (rate(construct_auth_failures_total[5m]))", "{{reason}}")],
      idle=True,
      desc="По причинам. Всплеск одной причины — это либо сломанный клиент, либо "
           "перебор; ровный фон по всем — обычно истёкшие токены.")

panel(R2, "Звонки", [("construct_active_calls", "активных сейчас"),
                     ("sum(rate(construct_calls_initiated_total[5m]))", "инициировано/с")],
      idle=True,
      desc="Активные звонки — gauge, инициации — счётчик. Расхождение (много "
           "инициаций, ноль активных) означает, что звонки не устанавливаются.")

panel(R2, "Ошибки сигналинга", [("sum by (error_type) (rate(construct_signaling_errors_total[5m]))", "{{error_type}}")],
      idle=True,
      desc="Ближайшее к причине, когда звонки не соединяются.")

R3 = "POSTGRES"

panel(R3, "Соединения по состоянию", [("sum by (state) (pg_stat_activity_count)", "{{state}}")],
      desc="max_connections = 50. Растущий idle in transaction — это утечка "
           "соединений в коде, а не нехватка ёмкости, и pgbouncer её не вылечит.")

panel(R3, "Попадание в кэш",
      [("sum(rate(pg_stat_database_blks_hit[5m])) / "
        "(sum(rate(pg_stat_database_blks_hit[5m])) + sum(rate(pg_stat_database_blks_read[5m])))", "hit ratio")],
      unit="percentunit",
      desc="Ниже ~0.99 на нагрузке — shared_buffers мал (сейчас 256MB) или запрос "
           "читает мимо индекса. Дешёвый ранний признак того, что БД пора тюнить, "
           "задолго до того, как это станет видно по задержкам.")

panel(R3, "Транзакции", [("sum(rate(pg_stat_database_xact_commit[5m]))", "commit/с"),
                         ("sum(rate(pg_stat_database_xact_rollback[5m]))", "rollback/с")],
      desc="Rollback заметно выше нуля — где-то падают запросы, а не «пользователи "
           "передумали».")

panel(R3, "Дедлоки и самая долгая транзакция",
      [("sum(rate(pg_stat_database_deadlocks[15m]))", "дедлоков/с"),
       ("max(pg_stat_activity_max_tx_duration)", "самая долгая транзакция, с")],
      desc="Долгая транзакция держит блокировки и не даёт вакууму убирать мёртвые "
           "строки — таблица пухнет молча.")

R4 = "REDIS — он же хранилище недоставленного"

panel(R4, "Ключей в базе", [("sum(redis_db_keys)", "ключей")],
      desc="Растёт вместе с офлайн-очередями. Сопоставлять с подрезками выше: "
           "ключи растут, подрезок нет — очереди никто не забирает.")

panel(R4, "Операций в секунду", [("rate(redis_commands_processed_total[5m])", "команд/с")],
      desc="Ёмкость по CPU у Redis наступит гораздо позже памяти, но резкий скачок "
           "при неизменном трафике сообщений — признак цикла в коде.")

panel(R4, "Клиенты", [("redis_connected_clients", "подключено"),
                      ("redis_blocked_clients", "заблокировано")],
      desc="Заблокированные клиенты — это ожидание на блокирующих командах; "
           "устойчиво ненулевое значение означает, что кто-то ждёт вместо работы.")

panel(R4, "Вытеснено / истекло", [("rate(redis_evicted_keys_total[15m])", "вытеснено/с"),
                                  ("rate(redis_expired_keys_total[15m])", "истекло по TTL/с")],
      desc="Вытеснение должно быть строго нулевым: политика noeviction. Любое "
           "движение верхней линии означает, что политику подменили и недоставленные "
           "сообщения могут исчезать без ошибки.")

R5 = "РЕСУРСЫ ПРОЦЕССОВ"

panel(R5, "Память процессов", [("process_resident_memory_bytes", "{{job}}")], unit="bytes", w=12,
      desc="RSS каждого сервиса. Ровный рост у одного при неизменном трафике — "
           "утечка; ищите там, а не в общей памяти хоста.")

panel(R5, "Открытые дескрипторы", [("process_open_fds", "{{job}}")], w=12,
      desc="Монотонный рост — соединения или файлы не закрываются. Упор в "
           "process_max_fds выглядит как отказ сети, а не как исчерпание лимита.")

# ── ЖДЁТ СОБЫТИЙ ────────────────────────────────────────────────────────────
R6 = "ЖДЁТ СОБЫТИЙ — производитель есть, событие не наступало"

panel(R6, "Звонки: соединено / пропущено / отклонено / неуспешно",
      [("sum(rate(construct_calls_connected_total[5m]))", "соединено"),
       ("sum(rate(construct_calls_missed_total[5m]))", "пропущено"),
       ("sum(rate(construct_calls_declined_total[5m]))", "отклонено"),
       ("sum(rate(construct_calls_failed_total[5m]))", "неуспешно")],
      idle=True, w=12,
      desc="Счётчики регистрируются при первом инкременте, поэтому до первого "
           "звонка серий нет. Пишет signaling-service — проверено по исходникам.")

panel(R6, "Деградация лимитера (fail-open)",
      [("sum by (control) (rate(construct_msg_abuse_fail_open_total[5m]))", "msg {{control}}"),
       ("sum by (control) (rate(construct_auth_security_fail_open_total[5m]))", "auth {{control}}")],
      idle=True, w=12,
      desc="Пусто = лимитер ни разу не деградировал, то есть желаемый исход. "
           "Появление линии означает, что Redis не отвечает на путь квот и лимиты "
           "стали приблизительными.")

panel(R6, "Канарейка: подписка без курсора",
      [("sum(increase(construct_msg_poll_missing_cursor_after_subscribe_total[1h]))", "за час")],
      idle=True, w=12,
      desc="Канарейка расследования про повторную доставку: сервер отматывал поток "
           "ниже присланного курсора, 3–8 повторов на сообщение. Любое значение "
           "выше нуля означает, что подписка пришла без пригодного курсора и окно "
           "воспроизведения выбрано наугад.")

panel(R6, "Устаревший путь редактирования",
      [("sum(rate(construct_legacy_edit_usage_total[1h]))", "вызовов/с")],
      idle=True, w=12,
      desc="Показывает, остались ли клиенты на старом формате правок. Ноль — можно "
           "удалять совместимость.")

# ── вывод ───────────────────────────────────────────────────────────────────

if sys.argv[1] == "probe":
    seen = []
    for p in P:
        for expr, _ in p["targets"]:
            if expr not in seen:
                seen.append(expr)
    print(json.dumps(seen))
    sys.exit(0)

results = json.load(open(sys.argv[2]))  # {expr: n_series}

dash = json.load(open(DASH))
# Keep the capacity row exactly as built and verified earlier today.
keep = []
in_cap = False
for pan in dash["panels"]:
    if pan["type"] == "row":
        in_cap = pan["title"].startswith("CAPACITY")
    if in_cap:
        keep.append(pan)

panels, pid, y = [], 100, 0
dropped, kept_idle = [], []
by_row = {}
for p in P:
    by_row.setdefault(p["row"], []).append(p)

for row, items in by_row.items():
    live = [p for p in items if results.get(p["targets"][0][0], 0) > 0 or p["idle"]]
    for p in items:
        if p not in live:
            dropped.append((row, p["title"], p["targets"][0][0]))
    if not live:
        continue
    panels.append({"collapsed": False, "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
                   "id": pid, "title": row, "type": "row"})
    pid += 1
    y += 1
    x = 0
    for p in live:
        if p["idle"] and results.get(p["targets"][0][0], 0) == 0:
            kept_idle.append((row, p["title"]))
        if x + p["w"] > 24:
            x = 0
            y += p["h"]
        fc = {"defaults": {"unit": p["unit"], "custom": {}}, "overrides": []}
        if p["kind"] == "timeseries":
            fc["defaults"]["color"] = {"mode": "palette-classic"}
            fc["defaults"]["custom"] = {"drawStyle": "line", "fillOpacity": 8,
                                        "lineWidth": 1, "showPoints": "never",
                                        "spanNulls": True}
        else:
            fc["defaults"]["color"] = {"mode": "thresholds"}
            if p["thresholds"]:
                fc["defaults"]["thresholds"] = {"mode": "absolute", "steps": p["thresholds"]}
        opts = {}
        if p["kind"] == "timeseries":
            opts = {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                    "tooltip": {"mode": "multi", "sort": "desc"}}
        elif p["kind"] == "stat":
            opts = {"colorMode": "value", "graphMode": "none", "justifyMode": "auto",
                    "orientation": "horizontal", "textMode": "auto",
                    "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}}
        panels.append({
            "datasource": DS, "fieldConfig": fc,
            "gridPos": {"h": p["h"], "w": p["w"], "x": x, "y": y},
            "id": pid, "options": opts, "title": p["title"], "description": p["desc"],
            "type": p["kind"],
            "targets": [{"datasource": DS, "expr": e, "legendFormat": lf,
                         "refId": chr(65 + i),
                         "instant": p["kind"] == "table", "format": "table" if p["kind"] == "table" else "time_series"}
                        for i, (e, lf) in enumerate(p["targets"])],
        })
        pid += 1
        x += p["w"]
    y += max(p["h"] for p in live)

# capacity row last, renumbered
for pan in keep:
    pan = dict(pan)
    pan["gridPos"] = dict(pan["gridPos"])
    pan["gridPos"]["y"] += y - 71
    panels.append(pan)

dash["panels"] = panels
dash["description"] = ("Construct — обзор сервера. Каждая панель построена от метрики, "
                       "которая действительно производится: выражения проверены против "
                       "работающего Prometheus при генерации.")
DASH.write_text(json.dumps(dash, indent=2, ensure_ascii=False) + "\n")

print(f"написано панелей: {len(panels)} (включая {len(keep)} из строки CAPACITY)")
if kept_idle:
    print("\nоставлены пустыми намеренно (производитель есть, событий не было):")
    for r, t in kept_idle:
        print(f"  · {t}")
if dropped:
    print("\nне включены — выражение не вернуло серий:")
    for r, t, e in dropped:
        print(f"  · {t}\n      {e}")
