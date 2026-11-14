"""Tests for external-tool discovery and the `danishrecon setup` installer. Offline:
network downloads are replaced by in-memory archives."""
import io
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

if "danishrecon.scan_core" not in sys.modules:
    os.chdir(tempfile.mkdtemp(prefix="danishrecon_tests_"))
os.environ["DISABLE_GEMINI"] = "true"

from danishrecon import tools, cli  # noqa: E402
from danishrecon import scan_core  # noqa: E402

PD_ASSETS = [{"name": n, "browser_download_url": "u/" + n} for n in (
    "katana_1.8.0_linux_amd64.zip", "katana_1.8.0_macOS_arm64.zip", "katana_1.8.0_windows_386.zip",
    "katana_1.8.0_windows_amd64.zip", "katana_1.8.0_checksums.txt")]
RS_ASSETS = [{"name": n, "browser_download_url": "u/" + n} for n in (
    "aarch64-macos-rustscan.tar.gz.zip", "x86-windows-rustscan.exe.zip", "x86_64-linux-rustscan.tar.gz.1.zip",
    "x86_64-linux-rustscan.tar.gz.zip", "x86_64-windows-rustscan.exe.zip")]


def _zip(files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return b.getvalue()


def _targz(files):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return b.getvalue()


class AssetSelection(unittest.TestCase):
    def test_projectdiscovery_assets(self):
        pick = tools.pick_pd_asset
        self.assertEqual(pick(PD_ASSETS, "katana", "windows", "amd64")["name"], "katana_1.8.0_windows_amd64.zip")
        self.assertEqual(pick(PD_ASSETS, "katana", "linux", "amd64")["name"], "katana_1.8.0_linux_amd64.zip")
        self.assertEqual(pick(PD_ASSETS, "katana", "macOS", "arm64")["name"], "katana_1.8.0_macOS_arm64.zip")
        self.assertIsNone(pick(PD_ASSETS, "katana", "freebsd", "amd64"))
        self.assertIsNone(pick(PD_ASSETS, "nuclei", "windows", "amd64"))

    def test_rustscan_assets(self):
        pick = tools.pick_rustscan_asset
        self.assertEqual(pick(RS_ASSETS, "Windows", "AMD64")["name"], "x86_64-windows-rustscan.exe.zip")
        self.assertEqual(pick(RS_ASSETS, "Linux", "x86_64")["name"], "x86_64-linux-rustscan.tar.gz.zip")
        self.assertEqual(pick(RS_ASSETS, "Darwin", "arm64")["name"], "aarch64-macos-rustscan.tar.gz.zip")
        self.assertIsNone(pick(RS_ASSETS, "SunOS", "sparc"))


class Extraction(unittest.TestCase):
    def test_binary_from_plain_zip(self):
        d = Path(tempfile.mkdtemp())
        out = tools._extract_binary(_zip({"README.md": b"x", "katana" + tools.EXE: b"BIN"}), "katana", d / "k")
        self.assertEqual(out.read_bytes(), b"BIN")

    def test_binary_from_zip_wrapping_targz(self):
        d = Path(tempfile.mkdtemp())
        inner = _targz({"rustscan" + tools.EXE: b"RS"})
        out = tools._extract_binary(_zip({"x86_64-linux-rustscan.tar.gz": inner}), "rustscan", d / "r")
        self.assertEqual(out.read_bytes(), b"RS")

    def test_missing_binary_raises(self):
        with self.assertRaises(RuntimeError):
            tools._extract_binary(_zip({"other": b"x"}), "katana", Path(tempfile.mkdtemp()) / "k")


class InstallersOffline(unittest.TestCase):
    def setUp(self):
        self.saved = (tools.TOOLS_DIR, tools.BIN_DIR, tools._download, tools._latest_release)
        tools.TOOLS_DIR = Path(tempfile.mkdtemp()) / "tools"
        tools.BIN_DIR = tools.TOOLS_DIR / "bin"

    def tearDown(self):
        tools.TOOLS_DIR, tools.BIN_DIR, tools._download, tools._latest_release = self.saved

    def test_install_nikto_lays_out_program_dir(self):
        tools._download = lambda url, log, max_mb=200: _zip({
            "sullo-nikto-abc123/program/nikto.pl": b"#!perl",
            "sullo-nikto-abc123/program/databases/db_tests": b""})
        path = tools.install_nikto(log=lambda *a: None)
        self.assertTrue(path.is_file())
        self.assertEqual(path, tools.TOOLS_DIR / "nikto" / "program" / "nikto.pl")

    def test_install_rustscan_puts_binary_in_tools_bin(self):
        import platform
        tools._latest_release = lambda repo: {"tag_name": "2.4.1", "assets": RS_ASSETS}
        tools._download = lambda url, log, max_mb=200: _zip({"rustscan" + tools.EXE: b"RS"})
        saved = (platform.system, platform.machine)
        platform.system, platform.machine = (lambda: "Windows"), (lambda: "AMD64")
        try:
            path = tools.install_rustscan(log=lambda *a: None)
        finally:
            platform.system, platform.machine = saved
        self.assertEqual(path.parent, tools.BIN_DIR)
        self.assertTrue(path.is_file())

    def test_install_exploitdb(self):
        tools._download = lambda url, log, max_mb=200: b"id,file,description\n"
        path = tools.install_exploitdb(log=lambda *a: None)
        self.assertEqual(path.name, "files_exploits.csv")
        self.assertTrue(path.is_file())


class Discovery(unittest.TestCase):
    def test_nikto_path_env_wins(self):
        f = Path(tempfile.mkdtemp()) / "nikto.pl"
        f.write_text("#")
        saved = os.environ.get("NIKTO_PATH")
        os.environ["NIKTO_PATH"] = str(f)
        try:
            self.assertEqual(tools.find_nikto(), str(f))
        finally:
            if saved is None:
                os.environ.pop("NIKTO_PATH", None)
            else:
                os.environ["NIKTO_PATH"] = saved

    def test_tools_bin_is_searched_first(self):
        from danishrecon import recon_tools
        self.assertEqual(recon_tools._candidates("katana")[0], str(tools.bin_path("katana")))

    def test_exploitdb_search_includes_tools_folder(self):
        from danishrecon import exploit_search
        self.assertIn(str(tools.TOOLS_DIR / "exploitdb"), exploit_search._CANDIDATE_DIRS)


class OpenVASReason(unittest.TestCase):
    def test_reason_when_gmp_client_missing(self):
        from danishrecon import openvas_scanner
        saved = openvas_scanner.GVM_AVAILABLE
        openvas_scanner.GVM_AVAILABLE = False
        try:
            self.assertIn("danishrecon[openvas]", scan_core.openvas_unavailable_reason())
        finally:
            openvas_scanner.GVM_AVAILABLE = saved

    def test_reason_when_docker_not_running(self):
        import socket
        from danishrecon import openvas_scanner
        saved = (openvas_scanner.GVM_AVAILABLE, openvas_scanner.GVM_PORT, tools.docker_running, scan_core.shutil.which)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free = s.getsockname()[1]
        openvas_scanner.GVM_AVAILABLE, openvas_scanner.GVM_PORT = True, free
        tools.docker_running = lambda: False
        scan_core.shutil.which = lambda name, *a, **k: "C:/docker.exe" if name == "docker" else None
        try:
            self.assertIn("Docker is not running", scan_core.openvas_unavailable_reason())
        finally:
            (openvas_scanner.GVM_AVAILABLE, openvas_scanner.GVM_PORT,
             tools.docker_running, scan_core.shutil.which) = saved


class SetupCommand(unittest.TestCase):
    def test_unknown_tool_is_rejected(self):
        self.assertEqual(cli.main(["setup", "not-a-tool"]), 2)

    def test_list_runs_without_installing(self):
        self.assertEqual(cli.main(["setup", "--list"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class GuiWithoutConsole(unittest.TestCase):
    """`danishrecon-gui` runs under pythonw, where sys.stdout/sys.stderr are None."""

    def test_gui_imports_and_builds_without_console_streams(self):
        try:
            import PyQt5  # noqa: F401
        except Exception:
            self.skipTest("PyQt5 not installed")
        import subprocess
        code = (
            "import os, sys, tempfile; os.chdir(tempfile.mkdtemp());"
            "os.environ['QT_QPA_PLATFORM']='offscreen'; os.environ['DISABLE_GEMINI']='true';"
            "os.environ['HOME']=os.environ['USERPROFILE']=tempfile.mkdtemp();"
            "sys.stdout=None; sys.stderr=None;"
            "from PyQt5.QtWidgets import QApplication; app=QApplication([]);"
            "from danishrecon import gui; w=gui.DanishReconMain();"
            "print('printing is safe');"
            "open(os.path.join(os.path.expanduser('~'),'ok.txt'),'w').write(gui.GUI_LOG)"
        )
        r = subprocess.run([sys.executable, "-W", "ignore", "-c", code], capture_output=True, text=True, timeout=180)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
