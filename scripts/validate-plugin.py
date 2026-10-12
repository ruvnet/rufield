#!/usr/bin/env python3
"""Validate RuField's local plugin packaging contract, using only stdlib.

This is deliberately not a replacement for `claude plugin validate`.
"""
import json
from pathlib import Path
import re
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(root):
    root = root.resolve()
    market = json.loads((root / '.claude-plugin/marketplace.json').read_text())
    require(market['name'] == 'rufield-marketplace', 'unexpected marketplace name')
    require(bool(market['owner']['name']), 'owner name missing')
    require(len(market['plugins']) == 1, 'expected one plugin')
    entry = market['plugins'][0]
    source = entry['source']
    require(isinstance(source, str) and source.startswith('./'), 'source must be local')
    require('..' not in Path(source).parts, 'source must not traverse')
    plugin = (root / source).resolve()
    require(plugin.is_relative_to(root), 'plugin escapes repository')
    manifest = json.loads((plugin / '.claude-plugin/plugin.json').read_text())
    require(manifest['name'] == entry['name'] == 'rufield', 'plugin names differ')
    require(re.fullmatch(r'\d+\.\d+\.\d+', manifest['version']), 'invalid version')
    require(bool(manifest['description']) and bool(manifest['author']['name']), 'missing metadata')
    require(not ({'hooks', 'mcpServers', 'settings'} & manifest.keys()), 'unexpected automatic runtime config')
    require(not (plugin / 'hooks').exists() and not (plugin / '.mcp.json').exists(), 'unexpected hooks or MCP')
    paths = sorted((plugin / 'skills').glob('*/SKILL.md'))
    require({p.parent.name for p in paths} == {'demo', 'replay', 'audit'}, 'unexpected skill inventory')
    for path in paths:
        require(path.resolve().is_relative_to(plugin), 'skill escapes plugin')
        body = path.read_text()
        parts = body.split('---\n', 2)
        require(len(parts) == 3 and parts[0] == '', f'{path}: missing frontmatter')
        fields = dict(line.split(': ', 1) for line in parts[1].splitlines())
        require(set(fields) == {'name', 'description'}, f'{path}: invalid fields')
        require(fields['name'] == path.parent.name, f'{path}: name mismatch')
        require(len(fields['description']) > 30, f'{path}: description too short')
        require('TODO' not in body and len(parts[2]) > 300, f'{path}: unfinished skill')
    print('PASS: marketplace, manifest, 3 skills, contained paths, no automatic hooks or MCP')


if __name__ == '__main__':
    try:
        validate(Path(__file__).resolve().parents[1])
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
