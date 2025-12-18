#!/usr/bin/env python3
"""
IDASQL Test Harness

Tests CLI (all 3 modes) and plugin server.

Usage:
    python run_tests.py [--skip-build] [--test-db path/to/test.i64]

Requirements:
    - IDASDK environment variable set
    - CMake in PATH
    - Python 3.6+

Exit codes:
    0 = all tests passed
    1 = tests failed
    2 = build failed
    3 = driver failed to start
"""
import os
import sys
import subprocess
import time
import argparse
import shutil
import re
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add current directory to path for importing test_client
sys.path.insert(0, str(Path(__file__).parent))
from test_client import IdasqlClient, run_basic_tests


def define_cli_local_tests() -> List[Dict[str, Any]]:
    """Define tests for CLI local modes (1 and 2)."""
    return [
        # Mode 1: Single query tests
        {
            'name': 'cli_local_count_funcs',
            'mode': 'query',
            'sql': 'SELECT COUNT(*) as count FROM funcs',
            'check': lambda out, rc: rc == 0 and 'count' in out and 'row(s)' in out,
        },
        {
            'name': 'cli_local_list_funcs',
            'mode': 'query',
            'sql': 'SELECT name, address FROM funcs LIMIT 3',
            'check': lambda out, rc: rc == 0 and 'name' in out and 'address' in out and '3 row(s)' in out,
        },
        {
            'name': 'cli_local_list_segments',
            'mode': 'query',
            'sql': 'SELECT name, start_ea FROM segments',
            'check': lambda out, rc: rc == 0 and 'name' in out,
        },
        {
            'name': 'cli_local_invalid_table',
            'mode': 'query',
            'sql': 'SELECT * FROM nonexistent_table',
            'check': lambda out, rc: rc != 0 and 'error' in out.lower(),
        },
        {
            'name': 'cli_local_syntax_error',
            'mode': 'query',
            'sql': 'SELECTT * FROM funcs',
            'check': lambda out, rc: rc != 0 and 'error' in out.lower(),
        },
        # Mode 2: Interactive mode tests
        {
            'name': 'cli_interactive_tables',
            'mode': 'interactive',
            'commands': ['.tables', '.quit'],
            'check': lambda out, rc: rc == 0 and 'funcs' in out and 'segments' in out,
        },
        {
            'name': 'cli_interactive_query',
            'mode': 'interactive',
            'commands': ['SELECT COUNT(*) as cnt FROM funcs;', '.quit'],
            'check': lambda out, rc: rc == 0 and 'cnt' in out,
        },
    ]


class TestHarness:
    def __init__(self, skip_build: bool = False, test_db: Optional[str] = None):
        self.skip_build = skip_build
        self.test_dir = Path(__file__).parent
        self.src_dir = self.test_dir.parent
        self.idasql_dir = self.src_dir.parent

        # Get IDASDK
        self.idasdk = os.environ.get('IDASDK')
        if not self.idasdk:
            raise RuntimeError("IDASDK environment variable not set")

        self.idasdk = Path(self.idasdk)
        self.idabin = self.idasdk / 'bin'

        # Test database
        if test_db:
            self.test_db = Path(test_db)
        else:
            # Default: use sample from ida-cmake
            self.test_db = self.idasdk / 'ida-cmake' / 'samples' / 'wizmo32.exe.i64'

        if not self.test_db.exists():
            raise RuntimeError(f"Test database not found: {self.test_db}")

        # Build config
        self.config = 'RelWithDebInfo'
        self.cli_config = 'Release'  # CLI uses Release build
        self.driver_process: Optional[subprocess.Popen] = None

        # CLI executable path
        self.cli_dir = self.src_dir / 'cli'
        if sys.platform == 'win32':
            self.cli_exe = self.cli_dir / 'build' / self.cli_config / 'idasql.exe'
        else:
            self.cli_exe = self.cli_dir / 'build' / self.cli_config / 'idasql'

    def log(self, msg: str):
        print(f"[harness] {msg}")

    def run_cmake(self, source_dir: Path, build_dir: Path) -> bool:
        """Configure and build with CMake."""
        self.log(f"Building {source_dir.name}...")

        # Configure
        result = subprocess.run(
            ['cmake', '-B', str(build_dir)],
            cwd=str(source_dir),
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            self.log(f"CMake configure failed:\n{result.stderr}")
            return False

        # Build
        result = subprocess.run(
            ['cmake', '--build', str(build_dir), '--config', self.config],
            cwd=str(source_dir),
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            self.log(f"CMake build failed:\n{result.stderr}")
            return False

        return True

    def build_all(self) -> bool:
        """Build plugin and driver."""
        if self.skip_build:
            self.log("Skipping build (--skip-build)")
            return True

        # Build plugin
        plugin_dir = self.src_dir / 'plugin'
        if not self.run_cmake(plugin_dir, plugin_dir / 'build'):
            return False

        # Copy plugin to IDA plugins directory
        plugin_build = plugin_dir / 'build' / self.config
        plugins_dest = self.idasdk / 'plugins'

        for dll in plugin_build.glob('idasql_plugin*.dll'):
            self.log(f"Copying {dll.name} to {plugins_dest}")
            shutil.copy2(dll, plugins_dest)

        for so in plugin_build.glob('idasql_plugin*.so'):
            self.log(f"Copying {so.name} to {plugins_dest}")
            shutil.copy2(so, plugins_dest)

        for dylib in plugin_build.glob('idasql_plugin*.dylib'):
            self.log(f"Copying {dylib.name} to {plugins_dest}")
            shutil.copy2(dylib, plugins_dest)

        # Build driver
        if not self.run_cmake(self.test_dir, self.test_dir / 'build'):
            return False

        # Build CLI
        if not self.build_cli():
            return False

        return True

    def build_cli(self) -> bool:
        """Build CLI tool."""
        self.log("Building CLI...")

        # Configure
        result = subprocess.run(
            ['cmake', '-B', 'build'],
            cwd=str(self.cli_dir),
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            self.log(f"CLI configure failed:\n{result.stderr}")
            return False

        # Build
        result = subprocess.run(
            ['cmake', '--build', 'build', '--config', self.cli_config],
            cwd=str(self.cli_dir),
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            self.log(f"CLI build failed:\n{result.stderr}")
            return False

        return True

    def get_cli_env(self) -> dict:
        """Get environment for running CLI."""
        env = os.environ.copy()
        if sys.platform == 'win32':
            env['PATH'] = f"{self.idabin};{env.get('PATH', '')}"
        elif sys.platform == 'darwin':
            env['DYLD_LIBRARY_PATH'] = f"{self.idabin}:{env.get('DYLD_LIBRARY_PATH', '')}"
        else:
            env['LD_LIBRARY_PATH'] = f"{self.idabin}:{env.get('LD_LIBRARY_PATH', '')}"
        return env

    def run_cli_local_tests(self) -> List[Dict[str, Any]]:
        """Run CLI local mode tests (modes 1 and 2)."""
        self.log("Running CLI local mode tests...")

        if not self.cli_exe.exists():
            self.log(f"CLI not found: {self.cli_exe}")
            return [{'name': 'cli_not_found', 'passed': False, 'error': 'CLI executable not found'}]

        env = self.get_cli_env()
        tests = define_cli_local_tests()
        results = []

        for test in tests:
            name = test['name']
            mode = test['mode']

            try:
                if mode == 'query':
                    # Mode 1: Single query
                    result = subprocess.run(
                        [str(self.cli_exe), '-s', str(self.test_db), '-q', test['sql']],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    output = result.stdout + result.stderr
                    passed = test['check'](output, result.returncode)

                elif mode == 'interactive':
                    # Mode 2: Interactive
                    input_text = '\n'.join(test['commands']) + '\n'
                    result = subprocess.run(
                        [str(self.cli_exe), '-s', str(self.test_db), '-i'],
                        env=env,
                        input=input_text,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    output = result.stdout + result.stderr
                    passed = test['check'](output, result.returncode)

                else:
                    passed = False
                    output = f"Unknown mode: {mode}"

                results.append({
                    'name': name,
                    'passed': passed,
                    'output': output[:500] if not passed else '',  # Truncate for failed tests
                    'returncode': result.returncode,
                })

            except subprocess.TimeoutExpired:
                results.append({
                    'name': name,
                    'passed': False,
                    'error': 'Timeout',
                })
            except Exception as e:
                results.append({
                    'name': name,
                    'passed': False,
                    'error': str(e),
                })

        return results

    def start_driver(self) -> bool:
        """Start idalib_driver in background."""
        self.log(f"Starting driver with {self.test_db.name}...")

        # Find driver executable
        driver_build = self.test_dir / 'build' / self.config
        if sys.platform == 'win32':
            driver_exe = driver_build / 'idalib_driver.exe'
        else:
            driver_exe = driver_build / 'idalib_driver'

        if not driver_exe.exists():
            self.log(f"Driver not found: {driver_exe}")
            return False

        # Setup environment
        env = os.environ.copy()
        if sys.platform == 'win32':
            env['PATH'] = f"{self.idabin};{env.get('PATH', '')}"
        elif sys.platform == 'darwin':
            env['DYLD_LIBRARY_PATH'] = f"{self.idabin}:{env.get('DYLD_LIBRARY_PATH', '')}"
        else:
            env['LD_LIBRARY_PATH'] = f"{self.idabin}:{env.get('LD_LIBRARY_PATH', '')}"

        # Start driver
        self.driver_process = subprocess.Popen(
            [str(driver_exe), str(self.test_db)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # Wait for server to start (look for "Server running" in output)
        self.log("Waiting for server to start...")
        start_time = time.time()
        timeout = 30  # seconds

        while time.time() - start_time < timeout:
            # Check if process died
            if self.driver_process.poll() is not None:
                output = self.driver_process.stdout.read()
                self.log(f"Driver exited unexpectedly:\n{output}")
                return False

            # Try connecting
            client = IdasqlClient()
            if client.connect(timeout=1.0):
                client.disconnect()
                self.log("Server is ready.")
                return True

            time.sleep(0.5)

        self.log("Timeout waiting for server")
        return False

    def stop_driver(self):
        """Stop the driver process."""
        if self.driver_process:
            self.log("Stopping driver...")
            self.driver_process.terminate()
            try:
                self.driver_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.driver_process.kill()
                self.driver_process.wait()

            # Print any remaining output
            output = self.driver_process.stdout.read()
            if output.strip():
                print(f"[driver output]\n{output}")

            self.driver_process = None

    def run_remote_tests(self) -> List[Dict[str, Any]]:
        """Run test queries against the plugin server (mode 3: remote)."""
        self.log("Running CLI remote mode tests...")

        client = IdasqlClient()
        if not client.connect():
            self.log("Failed to connect to server")
            return [{'name': 'remote_connect', 'passed': False, 'error': 'Failed to connect'}]

        results = run_basic_tests(client)
        client.disconnect()

        # Convert to common format
        return [
            {
                'name': f"cli_remote_{r['name']}",
                'passed': r['passed'],
                'sql': r.get('sql', ''),
                'error': r['result'].get('error', '') if not r['passed'] else '',
            }
            for r in results
        ]

    def print_results(self, results: List[Dict[str, Any]], title: str) -> tuple:
        """Print test results. Returns (passed, failed) counts."""
        print()
        print("=" * 60)
        print(title)
        print("=" * 60)

        passed = 0
        failed = 0
        for r in results:
            status = "PASS" if r['passed'] else "FAIL"
            print(f"[{status}] {r['name']}")
            if not r['passed']:
                if r.get('sql'):
                    print(f"        SQL: {r['sql']}")
                if r.get('error'):
                    print(f"        Error: {r['error']}")
                if r.get('output'):
                    # Show first line of output for debugging
                    first_line = r['output'].split('\n')[0][:80]
                    print(f"        Output: {first_line}...")

            if r['passed']:
                passed += 1
            else:
                failed += 1

        print()
        print(f"Subtotal: {passed} passed, {failed} failed")
        return passed, failed

    def run(self) -> int:
        """Run the full test harness. Returns exit code."""
        total_passed = 0
        total_failed = 0

        try:
            # Build
            if not self.build_all():
                return 2

            # ===== CLI Local Mode Tests (Modes 1 & 2) =====
            local_results = self.run_cli_local_tests()
            p, f = self.print_results(local_results, "CLI LOCAL MODE TESTS (Modes 1 & 2)")
            total_passed += p
            total_failed += f

            # ===== CLI Remote Mode Tests (Mode 3) =====
            # Start driver for remote tests
            if not self.start_driver():
                return 3

            remote_results = self.run_remote_tests()
            p, f = self.print_results(remote_results, "CLI REMOTE MODE TESTS (Mode 3)")
            total_passed += p
            total_failed += f

            # Print grand total
            print()
            print("=" * 60)
            print("GRAND TOTAL")
            print("=" * 60)
            print(f"Total: {total_passed} passed, {total_failed} failed")
            print("=" * 60)

            return 0 if total_failed == 0 else 1

        finally:
            self.stop_driver()


def main():
    parser = argparse.ArgumentParser(description='IDASQL Plugin Test Harness')
    parser.add_argument('--skip-build', action='store_true',
                        help='Skip building, use existing binaries')
    parser.add_argument('--test-db', type=str,
                        help='Path to test database (default: wizmo32.exe.i64)')
    args = parser.parse_args()

    try:
        harness = TestHarness(
            skip_build=args.skip_build,
            test_db=args.test_db
        )
        sys.exit(harness.run())
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
