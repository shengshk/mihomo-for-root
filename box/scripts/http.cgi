#!/system/bin/sh
# Same-origin, loopback-only browser bridge. No login or bearer token is used.
umask 077
export PATH=/data/adb/ksu/bin:/data/adb/magisk:/data/adb/ap/bin:$PATH
reject() {
  printf 'Status: %s\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\n\r\n{"error":"%s"}\n' "$1" "$2"
  exit 0
}
[ "$REQUEST_METHOD" = POST ] || reject '405 Method Not Allowed' '请使用管理页面操作。'
case "$HTTP_HOST" in 127.0.0.1:9091|localhost:9091) ;; *) reject '403 Forbidden' '不支持的访问地址。' ;; esac
case "${HTTP_ORIGIN:-}" in ''|http://127.0.0.1:9091|http://localhost:9091) ;; *) reject '403 Forbidden' '不允许跨站操作。' ;; esac
case "$CONTENT_TYPE" in application/json*) ;; *) reject '415 Unsupported Media Type' '请求格式无效。' ;; esac
case "$CONTENT_LENGTH" in ''|*[!0-9]*) reject '400 Bad Request' '请求长度无效。' ;; esac
[ "$CONTENT_LENGTH" -le 6291456 ] || reject '413 Content Too Large' '请求过大。'
action="$QUERY_STRING"
case "$action" in geodata-update|geodata-progress|defaults-get|defaults-save|defaults-restore|logs|status|apps|connection|settings-save|adg-enable|app-list-preview|upload-start|upload-chunk|profile-add|profile-edit|profile-activate|profile-update|profile-delete|panel-update|core-check|core-update|core-rollback|start|stop) ;; *) reject '400 Bad Request' '操作无效。' ;; esac
work=$(mktemp -d /data/adb/box/manage/.http.XXXXXXXX) || reject '500 Internal Server Error' '无法创建请求。'
trap 'rm -rf "$work"' EXIT
busybox head -c "$CONTENT_LENGTH" > "$work/request.json"
[ "$(wc -c < "$work/request.json")" = "$CONTENT_LENGTH" ] || reject '400 Bad Request' '请求不完整。'
if MFR_REQUEST_FILE="$work/request.json" /data/adb/box/scripts/box.manager "$action" > "$work/output" 2> "$work/error"; then
  printf 'Content-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n'
  cat "$work/output"
else
  printf 'Status: 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\n\r\n'
  MFR_ERROR="$(cat "$work/error")" /data/adb/box/bin/yq -n -o=json '{"error":strenv(MFR_ERROR)}'
fi
