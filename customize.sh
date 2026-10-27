#!/system/bin/sh
SKIPUNZIP=1
SKIPMOUNT=false
PROPFILE=true
POSTFSDATA=false
LATESTARTSERVICE=true
[ "$BOOTMODE" = true ] || abort '! 请在 Root 管理器内安装。'
case "$ARCH" in arm64) ;; *) abort '! 本个人版目前仅支持 Android ARM64。' ;; esac

unzip -o "$ZIPFILE" -x 'META-INF/*' -d "$MODPATH" >/dev/null || abort '! 解压失败。'
data=/data/adb/box
unattended=false
if [ -f "$data/.mfr-upgrade-unattended" ]; then
  unattended=true
  rm -f "$data/.mfr-upgrade-unattended"
fi
[ "${BOX_NONINTERACTIVE:-0}" != 1 ] || unattended=true
umask 077
mkdir -p /data/adb/box-backups
backup=$(mktemp -d /data/adb/box-backups/mfr-upgrade.XXXXXXXX) || abort '! 无法创建备份。'
if [ -d "$data" ]; then
  ui_print '- 备份现有配置、核心与模块数据'
  tar -cf "$backup/data.tar" -C /data/adb box || abort '! 备份失败，已停止安装。'
  cp -p "$data/settings.ini" "$backup/settings.ini" 2>/dev/null
  [ ! -d /data/adb/modules/box_for_root ] || cp -af /data/adb/modules/box_for_root "$backup/module"
fi
mkdir -p "$data/scripts" "$data/templates" "$data/bin" "$data/mihomo" "$data/run/state" /data/adb/service.d
# Keep all user configuration and resources. Only module code is replaced.
cp -af "$MODPATH/box/scripts/." "$data/scripts/" || abort '! 更新脚本失败。'
cp -af "$MODPATH/box/templates/." "$data/templates/" || abort '! 更新模板失败。'
mkdir -p "$data/lists"
cp -af "$MODPATH/box/lists/." "$data/lists/" || abort '! 安装内置应用清单失败。'
cp "$MODPATH/box/settings.ini" "$data/settings.ini" || abort '! 更新设置失败。'
if [ -s "$backup/settings.ini" ]; then
  for key in follow_network_dns network_dns_interval proxy_mode network_mode tproxy_port redir_port ipv6 bypass_cn_ip bypass_cn_ip_v4 bypass_cn_ip_v6; do
    old=$(sed -n "/^${key}=/p" "$backup/settings.ini" | head -n 1)
    [ -z "$old" ] || sed -i "s|^${key}=.*|${old}|" "$data/settings.ini"
  done
fi
for file in package.list.cfg gid.list.cfg ap.list.cfg crontab.cfg; do
  [ -f "$data/$file" ] || cp "$MODPATH/box/$file" "$data/$file"
done
[ -s "$data/mihomo/config.yaml" ] || cp "$data/templates/default.yaml" "$data/mihomo/config.yaml"
. "$data/scripts/geodata.utils"
mfr_seed_geodata "$MODPATH/assets/geodata" "$data/mihomo" || abort '! 安装初始 Geo 数据失败。'
for utility in yq curl agh-dns-bridge; do
  cp "$MODPATH/assets/arm64-v8a/$utility" "$data/bin/$utility.next" || abort '! 安装工具失败。'
  chmod 700 "$data/bin/$utility.next"
  mv "$data/bin/$utility.next" "$data/bin/$utility"
done
# AGH is optional; install its offline binary without enabling it or adding
# personal DNS rules. Existing AGH configuration and data survive upgrades.
[ -s "$data/bin/AdGuardHome" ] || cp "$MODPATH/assets/arm64-v8a/AdGuardHome" "$data/bin/AdGuardHome" || abort '! 安装 AGH 失败。'
chmod 700 "$data/bin/AdGuardHome"
mkdir -p "$data/adguardhome" "$data/licenses"
cp -af "$MODPATH/box/licenses/." "$data/licenses/" || abort '! 安装许可证失败。'
[ -s "$data/adguardhome/AdGuardHome.yaml" ] || cp "$data/templates/AdGuardHome.yaml" "$data/adguardhome/AdGuardHome.yaml"
if [ ! -s "$data/bin/mihomo" ]; then
  cp "$MODPATH/assets/arm64-v8a/mihomo" "$data/bin/mihomo" || abort '! 安装内核失败。'
  ui_print '- 已安装内置 Mihomo v1.19.33'
else
  ui_print '- 保留现有 Mihomo 内核'
fi
chmod 755 "$data/bin/mihomo"
chown root:net_admin "$data/bin/mihomo"
if [ ! -s "$data/mihomo/dashboard/index.html" ]; then
  mkdir -p "$data/mihomo/dashboard"
  unzip -o "$MODPATH/assets/dashboard.zip" -d "$data/mihomo/dashboard" >/dev/null || abort '! 安装面板失败。'
fi
# Old non-Mihomo files are archived rather than lost.
for core in sing-box xray v2fly hysteria; do
  [ ! -d "$data/$core" ] || mv "$data/$core" "$backup/$core"
  [ ! -f "$data/bin/$core" ] || mv "$data/bin/$core" "$backup/$core.binary"
done
cp "$MODPATH/box_service.sh" /data/adb/service.d/box_service.sh
chmod 755 /data/adb/service.d/box_service.sh "$MODPATH/action.sh" "$MODPATH/uninstall.sh"
chmod 644 "$MODPATH/webroot/"*
chmod 700 "$data/scripts/"*
chmod 600 "$data/settings.ini" "$data/mihomo/config.yaml"
if [ "$unattended" != true ]; then
  ui_print '- 是否下载官方最新稳定版内核？'
  ui_print '- 音量加：更新；音量减：保留；10 秒无操作默认保留'
  choice=$(timeout 10 getevent -ql 2>/dev/null | awk '/KEY_VOLUMEUP.*DOWN/ {print "update";exit} /KEY_VOLUMEDOWN.*DOWN/ {print "keep";exit}')
  if [ "$choice" = update ]; then
    if /system/bin/sh "$data/scripts/box.manager" core-update >/dev/null 2>&1; then
      ui_print '- 内核已更新并通过检查'
    else
      ui_print '- 更新失败，保留已有内核；可稍后在管理页重试'
    fi
  fi
fi
rm -rf "$MODPATH/box" "$MODPATH/assets" "$MODPATH/box_service.sh"
ui_print '- Mihomo For Root 1.0 安装完成'
ui_print '- 页面按钮：模块管理；操作按钮：启停代理'
ui_print "- 备份：$backup"
