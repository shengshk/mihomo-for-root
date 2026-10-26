#!/system/bin/sh

box_data_dir="/data/adb/box"
"${box_data_dir}/scripts/box.cron" stop >/dev/null 2>&1
"${box_data_dir}/scripts/box.policy" stop >/dev/null 2>&1
"${box_data_dir}/scripts/box.http" stop >/dev/null 2>&1
"${box_data_dir}/scripts/box.adg" stop >/dev/null 2>&1
rm_data() {
  if [ ! -d "${box_data_dir}" ]; then
    exit 1
  else
    rm -rf "${box_data_dir}"
  fi
  
  if [ -f "/data/adb/ksu/service.d/box_service.sh" ]; then
    rm -rf "/data/adb/ksu/service.d/box_service.sh"
  fi

  if [ -f "/data/adb/service.d/box_service.sh" ]; then
    rm -rf "/data/adb/service.d/box_service.sh"
  fi

}

rm_data
