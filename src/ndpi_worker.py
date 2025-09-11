import json
import threading
import subprocess
import shutil
import time


class NDPIWorker:
    """Optional nDPI integration via ndpiReader.

    Runs ndpiReader with JSON output and keeps a rolling map of 5‑tuple → labels.
    Safe no‑op if ndpiReader is not available.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self.proc = None
        self.thread = None
        self.running = False
        self.enabled = False
        self.labels = {}  # key: (src, dst, dport, proto) → {app, category, confidence}

    def start(self):
        if self.running:
            return False
        # Detect ndpiReader in PATH
        # Try PATH and common locations or explicit env var
        ndpi = (
            shutil.which('ndpiReader') or
            shutil.which('ndpiReader.exe') or
            os.environ.get('NDPI_READER_PATH') or
            self._find_common_windows_paths()
        )
        if not ndpi:
            self.enabled = False
            return False
        try:
            # -i iface, -J JSON, -v 2 verbose flows
            self.proc = subprocess.Popen(
                [ndpi, '-i', self.interface, '-J', '-v', '2'],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            self.running = True
            self.enabled = True
            self.thread = threading.Thread(target=self._reader_loop, daemon=True)
            self.thread.start()
            return True
        except Exception:
            self.enabled = False
            self.running = False
            return False

    def _find_common_windows_paths(self):
        try:
            import os
            candidates = [
                r"C:\\Program Files\\ndpi\\ndpiReader.exe",
                r"C:\\Program Files (x86)\\ndpi\\ndpiReader.exe",
                r"C:\\ndpi\\ndpiReader.exe",
                r"C:\\ProgramData\\chocolatey\\bin\\ndpiReader.exe"
            ]
            for p in candidates:
                if os.path.exists(p):
                    return p
        except Exception:
            pass
        return None

    def stop(self):
        self.running = False
        try:
            if self.proc:
                self.proc.terminate()
        except Exception:
            pass

    def _reader_loop(self):
        f = self.proc.stdout if self.proc else None
        while self.running and f:
            try:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                line = line.strip()
                if not line:
                    continue
                self._consume_json(line)
            except Exception:
                time.sleep(0.25)

    def _consume_json(self, line: str):
        try:
            obj = json.loads(line)
        except Exception:
            return
        # Heuristic: try common ndpiReader JSON fields
        try:
            src = obj.get('src_ip') or obj.get('ip_src')
            dst = obj.get('dst_ip') or obj.get('ip_dst')
            dport = obj.get('dst_port') or obj.get('port_dst')
            proto = obj.get('l4_proto') or obj.get('proto') or obj.get('ip_proto')
            app = obj.get('detected_protocol_name') or obj.get('app_name') or obj.get('protocol')
            category = obj.get('category') or obj.get('ndpi_category')
            conf = obj.get('confidence') or obj.get('risk') or 0.6
            if not (src and dst and dport and app):
                return
            key = (src, dst, int(dport), str(proto).upper())
            self.labels[key] = {
                'app': app,
                'category': category,
                'confidence': float(conf) if isinstance(conf, (int, float)) else 0.6
            }
            # Also store reverse direction
            rev = (dst, src, int(dport), str(proto).upper())
            if rev not in self.labels:
                self.labels[rev] = self.labels[key]
        except Exception:
            return

    def get_label(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str):
        if not self.enabled:
            return None
        key = (src_ip, dst_ip, int(dst_port or 0), str(protocol or '').upper())
        return self.labels.get(key)


