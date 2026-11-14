import requests
import threading
import queue
import time
import os

class DirBusterScanner:
    def __init__(self, target_url, wordlist_path, threads=20, extensions=None, log_callback=None, result_callback=None):
        self.target_url = target_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.extensions = extensions or ['php', 'html', 'txt']
        self.log_callback = log_callback
        self.result_callback = result_callback
        self.stop_event = threading.Event()
        self.findings = []
        self.queue = queue.Queue()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberRecon/1.0"
        }

    def _log(self, msg, level="info"):
        if self.log_callback:
            self.log_callback(msg, level)
        else:
            print(f"[{level.upper()}] {msg}")

    def worker(self):
        while not self.queue.empty() and not self.stop_event.is_set():
            path = self.queue.get()
            url = f"{self.target_url}/{path}"
            try:
                # Use HEAD request first for speed
                response = requests.head(url, headers=self.headers, timeout=5, allow_redirects=True)
                
                # If HEAD is not allowed or ambiguous, try GET
                if response.status_code in [405, 403]:
                    response = requests.get(url, headers=self.headers, timeout=5, stream=True)
                
                if response.status_code == 200:
                    result = f"Found: /{path} (200)"
                    self.findings.append(result)
                    if self.result_callback:
                        self.result_callback("DirBuster Findings", f"{result} (on {self.target_url})", "#10B981")
                    self._log(f"    [+] {result}", "good")
                
                elif response.status_code == 301 or response.status_code == 302:
                    loc = response.headers.get('Location', '')
                    result = f"Found: /{path} ({response.status_code}) -> {loc}"
                    self.findings.append(result)
                    if self.result_callback:
                        self.result_callback("DirBuster Findings", f"{result} (on {self.target_url})", "#3B82F6")
                    self._log(f"    [!] {result}", "info")

            except Exception:
                pass
            finally:
                self.queue.task_done()

    def run(self):
        if not os.path.exists(self.wordlist_path):
            self._log(f"Wordlist not found: {self.wordlist_path}", "error")
            return []

        self._log(f"Loading wordlist: {os.path.basename(self.wordlist_path)}", "muted")
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.queue.put(line)
        except Exception as e:
            self._log(f"Error reading wordlist: {e}", "error")
            return []

        total_words = self.queue.qsize()
        self._log(f"Starting brute force on {self.target_url} with {total_words} words...", "info")

        threads_list = []
        for _ in range(min(self.threads, total_words)):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads_list.append(t)

        # Wait for queue to be empty or stop event
        try:
            while not self.queue.empty() and not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_event.set()

        for t in threads_list:
            t.join(timeout=1)

        return self.findings

    def stop(self):
        self.stop_event.set()
