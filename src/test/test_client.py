#!/usr/bin/env python3
"""
IDASQL test client - connects to plugin server and runs queries.

Usage:
    python test_client.py [host] [port]
    python test_client.py localhost 13337

Can be used standalone or imported by test harness.
"""
import socket
import struct
import json
import sys
from typing import Optional, Dict, Any, List


class IdasqlClient:
    """Simple client for IDASQL server protocol."""

    def __init__(self, host: str = 'localhost', port: int = 13337):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None

    def connect(self, timeout: float = 5.0) -> bool:
        """Connect to server. Returns True on success."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            self.sock = None
            return False

    def disconnect(self):
        """Disconnect from server."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    def query(self, sql: str) -> Dict[str, Any]:
        """
        Execute SQL query and return result dict.

        Returns:
            {
                'success': True/False,
                'columns': [...],
                'rows': [[...], ...],
                'row_count': N,
                'error': '...'  # if success=False
            }
        """
        if not self.sock:
            return {'success': False, 'error': 'Not connected'}

        try:
            # Send request
            req = json.dumps({'sql': sql})
            req_bytes = req.encode('utf-8')
            self.sock.sendall(struct.pack('<I', len(req_bytes)) + req_bytes)

            # Receive response length
            len_bytes = self._recv_exact(4)
            if len_bytes is None:
                return {'success': False, 'error': 'Connection closed'}

            resp_len = struct.unpack('<I', len_bytes)[0]
            if resp_len > 100 * 1024 * 1024:  # 100MB limit
                return {'success': False, 'error': 'Response too large'}

            # Receive response
            resp_bytes = self._recv_exact(resp_len)
            if resp_bytes is None:
                return {'success': False, 'error': 'Connection closed'}

            return json.loads(resp_bytes.decode('utf-8'))

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes."""
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()


def run_basic_tests(client: IdasqlClient) -> List[Dict[str, Any]]:
    """Run basic test queries, return list of results."""
    tests = [
        {
            'name': 'count_funcs',
            'sql': 'SELECT COUNT(*) as count FROM funcs',
            'check': lambda r: r['success'] and len(r['rows']) == 1,
        },
        {
            'name': 'list_funcs',
            'sql': 'SELECT name, address, size FROM funcs LIMIT 5',
            'check': lambda r: r['success'] and 'name' in r['columns'],
        },
        {
            'name': 'list_segments',
            'sql': 'SELECT name, start_ea, end_ea FROM segments',
            'check': lambda r: r['success'],
        },
        {
            'name': 'list_names',
            'sql': 'SELECT address, name FROM names LIMIT 10',
            'check': lambda r: r['success'],
        },
        {
            'name': 'invalid_table',
            'sql': 'SELECT * FROM nonexistent_table',
            'check': lambda r: not r['success'] and 'error' in r,
        },
        {
            'name': 'syntax_error',
            'sql': 'SELECTT * FROM funcs',
            'check': lambda r: not r['success'] and 'error' in r,
        },
    ]

    results = []
    for test in tests:
        result = client.query(test['sql'])
        passed = test['check'](result)
        results.append({
            'name': test['name'],
            'sql': test['sql'],
            'passed': passed,
            'result': result,
        })

    return results


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 13337

    print(f"IDASQL Test Client")
    print(f"Connecting to {host}:{port}...")

    client = IdasqlClient(host, port)
    if not client.connect():
        print("ERROR: Failed to connect")
        sys.exit(1)

    print("Connected.\n")

    # Run tests
    results = run_basic_tests(client)

    # Print results
    passed = 0
    failed = 0
    for r in results:
        status = "PASS" if r['passed'] else "FAIL"
        print(f"[{status}] {r['name']}")
        print(f"       SQL: {r['sql']}")
        if r['result']['success']:
            print(f"       Rows: {r['result'].get('row_count', 0)}")
        else:
            print(f"       Error: {r['result'].get('error', 'unknown')}")
        print()

        if r['passed']:
            passed += 1
        else:
            failed += 1

    print(f"Results: {passed} passed, {failed} failed")

    client.disconnect()
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()
