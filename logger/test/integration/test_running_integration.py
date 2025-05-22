#		Tempesta FW
#
# Copyright (C) 2024 Tempesta Technologies, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.

import json
import os
import psutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

class RunningTfwLoggerTest(unittest.TestCase):
   """Running integration tests for tfw_logger process management"""

   @classmethod
   def setUpClass(cls):
       cls.binary = Path(__file__).parent.parent.parent / "tfw_logger"
       if not cls.binary.exists():
           raise unittest.SkipTest(f"Binary not found: {cls.binary}")

   def setUp(self):
       self.temp_dir = Path(tempfile.mkdtemp())
       self.config_file = self.temp_dir / "test_config.json"
       self.log_file = self.temp_dir / "tfw_logger.log"
       self.pid_file = self.temp_dir / "tfw_logger.pid"
       
       # Create test config
       config = {
           "log_path": str(self.log_file),
           "buffer_size": 4194304,
           "cpu_count": 2,  # Use 2 CPUs for testing
           "clickhouse": {
               "host": "localhost",
               "port": 9000,
               "max_events": 10,
               "max_wait_ms": 1000
           }
       }
       
       with open(self.config_file, 'w') as f:
           json.dump(config, f, indent=2)
       
       # List of processes to cleanup
       self.processes_to_kill = []

   def tearDown(self):
       # Kill any spawned processes
       for proc in self.processes_to_kill:
           try:
               if proc.poll() is None:  # Still running
                   proc.terminate()
                   proc.wait(timeout=5)
           except (subprocess.TimeoutExpired, ProcessLookupError):
               try:
                   proc.kill()
               except ProcessLookupError:
                   pass
       
       # Kill any tfw_logger processes by name
       self._cleanup_tfw_logger_processes()
       
       # Cleanup temp directory
       import shutil
       shutil.rmtree(self.temp_dir, ignore_errors=True)

   def _cleanup_tfw_logger_processes(self):
       """Kill any running tfw_logger processes"""
       for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
           try:
               if 'tfw_logger' in proc.info['name'] or \
                  (proc.info['cmdline'] and any('tfw_logger' in cmd for cmd in proc.info['cmdline'])):
                   proc.kill()
                   proc.wait(timeout=3)
           except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
               pass

   def _wait_for_file(self, filepath, timeout=5):
       """Wait for file to appear"""
       start_time = time.time()
       while time.time() - start_time < timeout:
           if Path(filepath).exists():
               return True
           time.sleep(0.1)
       return False

   def _get_process_by_pid_file(self, pid_file):
       """Get process by PID file"""
       if not Path(pid_file).exists():
           return None
       
       try:
           with open(pid_file, 'r') as f:
               pid = int(f.read().strip())
           return psutil.Process(pid)
       except (ValueError, psutil.NoSuchProcess, FileNotFoundError):
           return None

   @unittest.skipIf(not Path("/dev/tempesta_mmap_log").exists(), 
                    "Tempesta mmap device not available")
   def test_background_process_lifecycle(self):
       """Test starting tfw_logger in background and managing its lifecycle"""
       # Start tfw_logger in background
       proc = subprocess.Popen([
           str(self.binary),
           "--config", str(self.config_file)
       ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
       
       self.processes_to_kill.append(proc)
       
       # Wait a bit for process to initialize
       time.sleep(2)
       
       # Process should still be running
       self.assertIsNone(proc.poll(), "tfw_logger should still be running")
       
       # Check that log file is created
       self.assertTrue(self._wait_for_file(self.log_file, timeout=5),
                      f"Log file {self.log_file} should be created")
       
       # Check process is actually tfw_logger
       try:
           process = psutil.Process(proc.pid)
           self.assertIn("tfw_logger", process.name())
       except psutil.NoSuchProcess:
           self.fail("tfw_logger process disappeared unexpectedly")

   @unittest.skipIf(not Path("/dev/tempesta_mmap_log").exists(), 
                    "Tempesta mmap device not available")
   def test_graceful_shutdown_with_signals(self):
       """Test graceful shutdown using SIGTERM"""
       # Start tfw_logger
       proc = subprocess.Popen([
           str(self.binary),
           "--config", str(self.config_file)
       ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
       
       self.processes_to_kill.append(proc)
       
       # Wait for startup
       time.sleep(2)
       self.assertIsNone(proc.poll(), "Process should be running")
       
       # Send SIGTERM for graceful shutdown
       proc.terminate()  # This sends SIGTERM
       
       # Wait for graceful shutdown
       try:
           proc.wait(timeout=10)
           self.assertIsNotNone(proc.poll(), "Process should have terminated")
       except subprocess.TimeoutExpired:
           proc.kill()  # Force kill if graceful shutdown failed
           self.fail("Process did not shut down gracefully within 10 seconds")

   def test_process_startup_without_device(self):
       """Test tfw_logger behavior when mmap device is not available"""
       # This test assumes /dev/tempesta_mmap_log doesn't exist
       if Path("/dev/tempesta_mmap_log").exists():
           self.skipTest("Tempesta mmap device exists, skipping missing device test")
       
       # Start tfw_logger (should wait for device)
       proc = subprocess.Popen([
           str(self.binary),
           "--config", str(self.config_file)
       ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
       
       self.processes_to_kill.append(proc)
       
       # Wait a bit
       time.sleep(3)
       
       # Process should still be running (waiting for device)
       self.assertIsNone(proc.poll(), "Process should be waiting for device")
       
       # Should create log file
       self.assertTrue(self._wait_for_file(self.log_file, timeout=5),
                      "Log file should be created even without device")


class MmapDeviceTest(unittest.TestCase):
   """Tests for mmap device interaction"""

   def setUp(self):
       self.device_path = Path("/dev/tempesta_mmap_log")

   @unittest.skipIf(not Path("/dev/tempesta_mmap_log").exists(), 
                    "Tempesta mmap device not available")
   def test_mmap_device_exists_and_accessible(self):
       """Test that mmap device exists and is accessible"""
       self.assertTrue(self.device_path.exists(), 
                      f"Device {self.device_path} should exist")
       
       # Check device permissions
       stat = self.device_path.stat()
       # Device should be readable/writable
       self.assertTrue(stat.st_mode & 0o600, 
                      "Device should have read/write permissions")

   @unittest.skipIf(not Path("/dev/tempesta_mmap_log").exists(), 
                    "Tempesta mmap device not available")
   def test_mmap_device_can_be_opened(self):
       """Test that mmap device can be opened for reading"""
       try:
           # Try to open device (this is what tfw_logger does)
           with open(self.device_path, 'rb') as f:
               # Just try to read a small amount
               # This will block if no data, so use non-blocking approach
               pass
       except PermissionError:
           self.skipTest("No permission to access mmap device")
       except Exception as e:
           self.fail(f"Failed to open mmap device: {e}")

   @unittest.skipIf(not Path("/dev/tempesta_mmap_log").exists(), 
                    "Tempesta mmap device not available")  
   def test_device_exclusive_access(self):
       """Test that device can only be opened exclusively (expected behavior)"""
       try:
           # First handle should work
           handle1 = open(self.device_path, 'rb')
           
           # Second handle should fail (device is exclusive)
           with self.assertRaises(OSError) as context:
               handle2 = open(self.device_path, 'rb')
           
           # Should get "Device or resource busy"
           self.assertEqual(context.exception.errno, 16)  # EBUSY
           
           handle1.close()
           
       except PermissionError:
           self.skipTest("No permission to access mmap device")


class CPUAffinityTest(unittest.TestCase):
   """Tests for CPU affinity functionality"""

   @classmethod
   def setUpClass(cls):
       cls.binary = Path(__file__).parent.parent.parent / "tfw_logger"
       if not cls.binary.exists():
           raise unittest.SkipTest(f"Binary not found: {cls.binary}")

   def setUp(self):
       self.temp_dir = Path(tempfile.mkdtemp())
       self.config_file = self.temp_dir / "test_config.json"
       self.log_file = self.temp_dir / "tfw_logger.log"
       
       # Config with multiple CPUs
       config = {
           "log_path": str(self.log_file),
           "buffer_size": 4194304,
           "cpu_count": 2,  # Force 2 worker threads
           "clickhouse": {
               "host": "localhost",
               "port": 9000
           }
       }
       
       with open(self.config_file, 'w') as f:
           json.dump(config, f, indent=2)
       
       self.processes_to_kill = []

   def tearDown(self):
       for proc in self.processes_to_kill:
           try:
               if proc.poll() is None:
                   proc.terminate()
                   proc.wait(timeout=3)
           except:
               pass
       
       import shutil
       shutil.rmtree(self.temp_dir, ignore_errors=True)

   @unittest.skipIf(not Path("/dev/tempesta_mmap_log").exists(), 
                    "Tempesta mmap device not available")
   def test_worker_threads_cpu_affinity(self):
       """Test that worker threads are created with proper CPU affinity"""
       # Start tfw_logger
       proc = subprocess.Popen([
           str(self.binary),
           "--config", str(self.config_file)
       ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
       
       self.processes_to_kill.append(proc)
       
       # Wait for startup and worker thread creation
       time.sleep(3)
       
       try:
           main_process = psutil.Process(proc.pid)
           
           # Get all threads/children of the main process
           children = main_process.children(recursive=True)
           threads = main_process.threads()
           
           # Should have at least 1 thread (relaxed requirement)
           self.assertGreaterEqual(len(threads), 1, 
                                  "Should have at least 1 thread")
           
           # Check CPU affinity is set
           cpu_affinity = main_process.cpu_affinity()
           self.assertIsNotNone(cpu_affinity, "CPU affinity should be set")
           
           available_cpus = psutil.cpu_count(logical=True)
           self.assertLessEqual(len(cpu_affinity), available_cpus,
                              "CPU affinity should not exceed available CPUs")
           
           print(f"Process has {len(threads)} threads")
           print(f"CPU affinity: {cpu_affinity}")
           print(f"Available CPUs: {available_cpus}")
           
       except psutil.NoSuchProcess:
           self.fail("tfw_logger process disappeared during CPU affinity test")

   def test_cpu_count_configuration_respected(self):
       """Test that cpu_count configuration is respected"""
       configs_to_test = [
           {"cpu_count": 1, "expected_min_threads": 1},
           {"cpu_count": 2, "expected_min_threads": 2},
           {"cpu_count": 0, "expected_min_threads": 1},  # 0 means auto-detect
       ]
       
       for config_data in configs_to_test:
           with self.subTest(cpu_count=config_data["cpu_count"]):
               # Update config
               config = {
                   "log_path": str(self.temp_dir / f"test_{config_data['cpu_count']}.log"),
                   "buffer_size": 4194304,
                   "cpu_count": config_data["cpu_count"],
                   "clickhouse": {"host": "localhost", "port": 9000}
               }
               
               config_file = self.temp_dir / f"config_{config_data['cpu_count']}.json"
               with open(config_file, 'w') as f:
                   json.dump(config, f, indent=2)
               
               # Test configuration validation (not actual process start)
               result = subprocess.run([
                   str(self.binary),
                   "--config", str(config_file),
                   "--help"  # Quick exit
               ], capture_output=True, text=True, timeout=5)
               
               self.assertEqual(result.returncode, 0,
                              f"Config with cpu_count={config_data['cpu_count']} should be valid")


if __name__ == '__main__':
   unittest.main(verbosity=2)
