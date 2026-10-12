#!/usr/bin/env python3
"""Exercise built benchmark and viewer binaries over real local HTTP/SSE.
Run: cargo build -p rufield-bench -p rufield-viewer && python3 scripts/verify-e2e.py
No hardware or physical accuracy claim is made.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from urllib.request import urlopen
from urllib.error import URLError

ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target')) / 'debug'

def benchmark():
    data = json.loads(subprocess.check_output([str(TARGET/'rufield-bench'), '2026', '--json']))
    assert data['synthetic'] is True
    assert data['events_total'] > 0 and data['modalities'] >= 3
    assert data['privacy_violations'] == 0
    assert data['provenance_coverage_pct'] == 100
    for key in ('p95_latency_ms', 'p50_latency_ms'):
        assert data.pop(key) >= 0
    return data


def main():
    assert benchmark() == benchmark(), 'same-seed semantic report changed'
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    env = {k:v for k,v in os.environ.items() if not k.startswith('RUFIELD_VIEWER_')}
    proc = subprocess.Popen([str(TARGET/'rufield-viewer'), '--source', 'synthetic',
                             '--port', str(port), '--tick-ms', '1', '--no-loop'],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    base = f'http://127.0.0.1:{port}'
    def get(path):
        with urlopen(base+path, timeout=10) as response:
            return response.read()
    try:
        for _ in range(100):
            if proc.poll() is not None:
                raise AssertionError(proc.stderr.read().decode())
            try:
                health = json.loads(get('/health'))
                break
            except (URLError, ConnectionError):
                time.sleep(.05)
        else:
            raise AssertionError('viewer did not start within five seconds')
        assert health['status'] == 'ok' and health['synthetic'] is True
        source = json.loads(get('/api/source'))
        assert source['source'] == 'synthetic' and source['banner']['state'] == 'synthetic'
        assert b'SYNTHETIC' in get('/')
        assert get('/app.js')
        run = json.loads(get('/api/run'))
        assert run['frames']
        with urlopen(base+'/events', timeout=10) as response:
            assert response.headers['Content-Type'].startswith('text/event-stream')
            wire=response.read().decode('utf-8')
        assert 'event: meta' in wire and 'event: frame' in wire and 'event: done' in wire
        print('PASS: deterministic benchmark; zero privacy violations; HTTP dashboard; complete SSE lifecycle')
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        proc.stderr.close()

if __name__ == '__main__':
    main()
