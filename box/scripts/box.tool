#!/system/bin/sh
scripts_dir="${0%/*}"
. /data/adb/box/settings.ini
case "$1" in
  reload) exec "$scripts_dir/box.service" reload ;;
  check) exec "$scripts_dir/box.service" validate "$mihomo_config" ;;
  upkernel) exec "$scripts_dir/box.manager" core-update ;;
  core-check) exec "$scripts_dir/box.manager" core-check ;;
  upxui) exec "$scripts_dir/box.manager" panel-update ;;
  webroot)
    [ -s /data/adb/modules/box_for_root/webroot/index.html ] && [ -s /data/adb/modules/box_for_root/webroot/manage.html ]
    ;;
  *) printf '%s\n' '用法: box.tool check|reload|upkernel|core-check|upxui|webroot' >&2; exit 1 ;;
esac
