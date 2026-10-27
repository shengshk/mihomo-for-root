#!/usr/bin/env python3
"""Verify the versioned offline module and its public dependencies."""
import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]

def verify(archive_only=False):
    metadata = json.loads((ROOT / 'releases/module.json').read_text())
    archive = ROOT / 'releases' / metadata['file']
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != metadata['sha256']:
        raise ValueError('成品 SHA256 与 releases/module.json 不一致')
    checksums = (ROOT / 'releases/SHA256SUMS').read_text().split()
    if checksums != [digest, archive.name]:
        raise ValueError('SHA256SUMS 与成品不一致')
    with zipfile.ZipFile(archive) as package:
        bad = package.testzip()
        if bad:
            raise ValueError(f'ZIP 损坏: {bad}')
        names = [entry.filename for entry in package.infolist() if not entry.is_dir()]
        if len(names) != len(set(names)):
            raise ValueError('ZIP 包含重复路径')
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('ZIP 路径无效')
            if not name.startswith(('META-INF/', 'box/', 'webroot/', 'assets/')) and name not in (
                'action.sh', 'box_service.sh', 'customize.sh', 'module.prop', 'uninstall.sh', 'LICENSE'
            ):
                raise ValueError(f'ZIP 中存在非安装文件: {name}')
            if not archive_only and not name.startswith('assets/'):
                source = ROOT / name
                if not source.is_file() or source.read_bytes() != package.read(name):
                    raise ValueError(f'成品与当前模块源码不一致: {name}')
        properties = dict(line.split('=', 1) for line in package.read('module.prop').decode().splitlines() if '=' in line)
        if properties['version'] != metadata['version'] or int(properties['versionCode']) != metadata['versionCode']:
            raise ValueError('成品版本与发布记录不一致')
        dependencies = json.loads(package.read('assets/VERSIONS.json'))
        if not archive_only:
            bridge = dependencies['files']['arm64-v8a/agh-dns-bridge']
            if bridge['source_sha256'] != hashlib.sha256((ROOT / 'scripts/agh-dns-bridge/main.go').read_bytes()).hexdigest():
                raise ValueError('DNS 转发器与当前源码不一致')
        for name, info in dependencies['files'].items():
            content = package.read('assets/' + name)
            if len(content) != info['bytes'] or hashlib.sha256(content).hexdigest() != info['sha256']:
                raise ValueError(f'内置依赖校验失败: {name}')
    print(f'PASS release: {archive.name}, {digest}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive-only', action='store_true', help='校验归档及依赖，不对照当前源码')
    args = parser.parse_args()
    try:
        verify(args.archive_only)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        sys.exit(str(error))
