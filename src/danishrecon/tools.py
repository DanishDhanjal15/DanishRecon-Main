"""
External-tool locations and installer.

pip installs DanishRecon's Python code only. The scanners it drives (Nikto, katana, nuclei,
httpx, subfinder, rustscan) and the Exploit-DB index are separate projects. This module

  * defines one per-user tools folder that every part of DanishRecon searches, so a tool
    installed once works no matter which directory a scan is started from, and
  * installs those tools into it from their official sources (``danishrecon setup``).

Tools folder: ``~/.danishrecon/tools`` (override with ``DANISHRECON_TOOLS``)
    bin/            downloaded binaries (katana, nuclei, httpx, subfinder, rustscan)
    nikto/          Nikto checkout  (program/nikto.pl)
    exploitdb/      files_exploits.csv
    openvas/        docker-compose.yml for the OpenVAS container
"""
from __future__ import annotations

import io
import os
import platform
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Callable, Dict, List, Optional

TOOLS_DIR = Path(os.environ.get("DANISHRECON_TOOLS") or (Path.home() / ".danishrecon" / "tools"))
BIN_DIR = TOOLS_DIR / "bin"
EXE = ".exe" if os.name == "nt" else ""

PD_TOOLS = ("nuclei", "katana", "httpx", "subfinder")
NIKTO_ZIP = "https://api.github.com/repos/sullo/nikto/zipball"
EXPLOITDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

Log = Callable[[str], None]


# ─────────────────────────────── locations ────────────────────────────────

def bin_path(name: str) -> Path:
    return BIN_DIR / (name + EXE)


def nikto_candidates() -> List[str]:
    cwd = os.getcwd()
    return [
        os.environ.get("NIKTO_PATH", ""),
        str(TOOLS_DIR / "nikto" / "program" / "nikto.pl"),
        os.path.join(cwd, "nikto_official", "program", "nikto.pl"),
        os.path.join(cwd, "nikto", "program", "nikto.pl"),
        "/opt/nikto/program/nikto.pl",
        "/usr/share/nikto/nikto.pl",
        shutil.which("nikto.pl") or "",
        shutil.which("nikto") or "",
    ]


def find_nikto() -> Optional[str]:
    for p in nikto_candidates():
        if p and os.path.isfile(p):
            return p
    return None


def exploitdb_dirs() -> List[str]:
    return [
        os.environ.get("EXPLOITDB_PATH", ""),
        str(TOOLS_DIR / "exploitdb"),
        os.path.join(os.getcwd(), "exploit-database"),
        "/usr/share/exploitdb",
        "/opt/exploitdb",
        "/opt/exploit-database",
    ]


def openvas_compose_path() -> Path:
    return TOOLS_DIR / "openvas" / "docker-compose.yml"


# ─────────────────────────────── helpers ──────────────────────────────────

def _platform_tags():
    """(os_tag, arch_tag) as used by ProjectDiscovery release asset names."""
    system = platform.system().lower()
    os_tag = {"windows": "windows", "linux": "linux", "darwin": "macOS"}.get(system, system)
    m = platform.machine().lower()
    arch = "arm64" if m in ("arm64", "aarch64") else "386" if m in ("i386", "i686", "x86") else "amd64"
    return os_tag, arch


def _download(url: str, log: Log, max_mb: int = 200) -> bytes:
    import requests
    log(f"    downloading {url}")
    with requests.get(url, stream=True, timeout=60, headers={"User-Agent": "danishrecon-setup"}) as r:
        r.raise_for_status()
        buf = io.BytesIO()
        for chunk in r.iter_content(1 << 16):
            buf.write(chunk)
            if buf.tell() > max_mb * 1024 * 1024:
                raise RuntimeError(f"download larger than {max_mb} MB - aborted")
    log(f"    {buf.tell() // 1024} KB")
    return buf.getvalue()


def _latest_release(repo: str) -> dict:
    import requests
    r = requests.get(f"https://api.github.com/repos/{repo}/releases/latest", timeout=30,
                     headers={"Accept": "application/vnd.github+json", "User-Agent": "danishrecon-setup"})
    r.raise_for_status()
    return r.json()


def pick_pd_asset(assets: List[dict], tool: str, os_tag: str, arch: str) -> Optional[dict]:
    """Choose e.g. ``katana_1.8.0_windows_amd64.zip`` from a release's assets."""
    suffix = f"_{os_tag}_{arch}.zip".lower()
    for a in assets:
        n = a.get("name", "").lower()
        if n.startswith(tool + "_") and n.endswith(suffix):
            return a
    return None


def pick_rustscan_asset(assets: List[dict], system: str, machine: str) -> Optional[dict]:
    """Choose e.g. ``x86_64-windows-rustscan.exe.zip`` from RustScan's release assets."""
    system = system.lower()
    os_key = {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(system)
    if not os_key:
        return None
    m = machine.lower()
    arch = "aarch64" if m in ("arm64", "aarch64") else "x86_64" if m in ("x86_64", "amd64") else "x86"
    exact = [a for a in assets if a.get("name", "").lower().startswith(f"{arch}-{os_key}-rustscan")]
    exact.sort(key=lambda a: len(a["name"]))      # prefer the clean name over a ".1" duplicate upload
    return exact[0] if exact else None


def _extract_binary(blob: bytes, name: str, dest: Path) -> Path:
    """Pull the executable called ``name`` out of a zip (which may itself wrap a .tar.gz)."""
    target = name + EXE
    dest.parent.mkdir(parents=True, exist_ok=True)

    def from_zip(data):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                base = os.path.basename(info.filename)
                if base == target:
                    return z.read(info)
                if base.endswith((".tar.gz", ".tgz")):
                    return from_tar(z.read(info))
        return None

    def from_tar(data):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
            for m in t.getmembers():
                if m.isfile() and os.path.basename(m.name) == target:
                    return t.extractfile(m).read()
        return None

    payload = from_zip(blob)
    if payload is None:
        raise RuntimeError(f"{target} not found in the downloaded archive")
    dest.write_bytes(payload)
    if os.name != "nt":
        dest.chmod(0o755)
    return dest


# ─────────────────────────────── installers ───────────────────────────────

def install_pd_tool(tool: str, log: Log = print) -> Path:
    os_tag, arch = _platform_tags()
    rel = _latest_release(f"projectdiscovery/{tool}")
    asset = pick_pd_asset(rel.get("assets", []), tool, os_tag, arch)
    if not asset:
        raise RuntimeError(f"no {tool} release for {os_tag}/{arch}")
    log(f"  {tool} {rel.get('tag_name')} ({asset['name']})")
    path = _extract_binary(_download(asset["browser_download_url"], log), tool, bin_path(tool))
    log(f"    installed -> {path}")
    if tool == "nuclei":
        log("    fetching nuclei templates (first run takes a minute)...")
        subprocess.run([str(path), "-update-templates", "-silent"], timeout=600,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return path


def install_rustscan(log: Log = print) -> Path:
    rel = _latest_release("bee-san/RustScan")
    asset = pick_rustscan_asset(rel.get("assets", []), platform.system(), platform.machine())
    if not asset:
        raise RuntimeError("no RustScan binary for this platform - try: cargo install rustscan")
    log(f"  rustscan {rel.get('tag_name')} ({asset['name']})")
    path = _extract_binary(_download(asset["browser_download_url"], log), "rustscan", bin_path("rustscan"))
    log(f"    installed -> {path}")
    return path


def install_nikto(log: Log = print) -> Path:
    """Download Nikto (the official sullo/nikto repository) into the tools folder."""
    dest = TOOLS_DIR / "nikto"
    blob = _download(NIKTO_ZIP, log)
    tmp = TOOLS_DIR / "nikto.tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        z.extractall(tmp)
    inner = next(p for p in tmp.iterdir() if p.is_dir())        # sullo-nikto-<sha>/
    if dest.exists():
        shutil.rmtree(dest)
    shutil.move(str(inner), str(dest))
    shutil.rmtree(tmp, ignore_errors=True)
    script = dest / "program" / "nikto.pl"
    if not script.is_file():
        raise RuntimeError("nikto.pl missing after download (antivirus may have removed it)")
    log(f"    installed -> {script}")
    if not shutil.which("perl"):
        log("    NOTE: Nikto needs Perl. Windows: install Strawberry Perl (https://strawberryperl.com).")
    return script


def install_exploitdb(log: Log = print) -> Path:
    dest = TOOLS_DIR / "exploitdb" / "files_exploits.csv"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(_download(EXPLOITDB_CSV, log, max_mb=100))
    log(f"    installed -> {dest}")
    return dest


OPENVAS_COMPOSE = """# OpenVAS / Greenbone for DanishRecon (GMP on 127.0.0.1:9390, web UI on 127.0.0.1:9392).
# First start downloads the vulnerability feeds and can take 20-30 minutes.
services:
  greenbone:
    image: securecompliance/gvm:latest
    container_name: danishrecon-openvas
    environment:
      - PASSWORD=${GVM_PASSWORD:-admin}
    ports:
      - "127.0.0.1:9390:9390"
      - "127.0.0.1:9392:9392"
    volumes:
      - gvm-data:/data
    restart: unless-stopped
volumes:
  gvm-data:
"""


def docker_running() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        r = subprocess.run([docker, "info", "--format", "{{.ServerVersion}}"],
                           capture_output=True, text=True, timeout=20)
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


def setup_openvas(log: Log = print) -> Path:
    path = openvas_compose_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(OPENVAS_COMPOSE, encoding="utf-8")
    log(f"    compose file -> {path}")
    try:
        import gvm  # noqa: F401
    except Exception:
        log('    NOTE: install the GMP client too:  pip install "danishrecon[openvas]"')
    if not shutil.which("docker"):
        raise RuntimeError("Docker is not installed - get Docker Desktop: https://docs.docker.com/desktop/")
    if not docker_running():
        raise RuntimeError("Docker is installed but not running - start Docker Desktop, then run this again")
    log("    starting the OpenVAS container (first start downloads feeds: 20-30 min)...")
    r = subprocess.run(["docker", "compose", "-f", str(path), "up", "-d"],
                       capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError("docker compose failed: " + (r.stderr or r.stdout)[-400:])
    log("    container started. Check progress:  docker logs -f danishrecon-openvas")
    return path


INSTALLERS = {
    "nikto": install_nikto,
    "exploitdb": install_exploitdb,
    "rustscan": install_rustscan,
    "openvas": setup_openvas,
    **{t: (lambda t=t: (lambda log=print: install_pd_tool(t, log)))() for t in PD_TOOLS},
}
DEFAULT_SET = ("nuclei", "katana", "httpx", "subfinder", "nikto", "exploitdb", "rustscan")


# ─────────────────────────────── status ───────────────────────────────────

def status() -> Dict[str, Optional[str]]:
    """Where each optional tool was found (None = missing)."""
    from danishrecon import recon_tools, exploit_search
    from danishrecon.scan_core import find_rustscan
    out: Dict[str, Optional[str]] = {}
    for t in PD_TOOLS:
        recon_tools._tool_cache.pop(t, None)
        out[t] = recon_tools.find_tool(t)
    out["nikto"] = find_nikto()
    out["exploitdb"] = exploit_search.find_index()
    out["rustscan"] = find_rustscan()
    out["openvas"] = ("container running" if _openvas_port_open() else None)
    return out


def _openvas_port_open() -> bool:
    import socket
    try:
        with socket.create_connection(("127.0.0.1", 9390), timeout=1):
            return True
    except OSError:
        return False
