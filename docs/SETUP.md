# Setting up DanishRecon on a new machine

`pip install danishrecon` installs the Python code only. The scanners it drives (nmap,
nuclei, katana, Nikto, Wireshark/tshark, ...) are separate programs. Do this once per
machine and scans will not stop half-way with "not installed" messages.

What you need depends on what you run:

| You want to | Required | Recommended | Optional |
|---|---|---|---|
| `danishrecon scan` (recon + web vulns) | Python, **nmap** | nuclei, katana, httpx, subfinder, Nikto + Perl | Exploit-DB index, rustscan, OpenVAS (Docker) |
| `danishrecon malware` | Python, `[malware]` extra | - | - |
| `danishrecon sniff` | Python, **Wireshark (tshark)** | - | admin rights for `--live` |
| `danishrecon-gui` | Python, `[gui]` extra, nmap | as for `scan` | - |
| `danishrecon-web` | Python, `[web]` extra, nmap | as for `scan` | - |

Steps 1-5 below are the same idea on every OS; pick your section.

---

## Windows 10 / 11

Open **PowerShell** (normal, not admin, unless a step says so).

**1. Python 3.10+**
Install from https://www.python.org/downloads/ and tick **"Add python.exe to PATH"**,
or: `winget install Python.Python.3.12`. Close and reopen PowerShell, then check:
```powershell
python --version
```

**2. DanishRecon in its own virtual environment**
```powershell
python -m venv $env:USERPROFILE\danishrecon-venv
& $env:USERPROFILE\danishrecon-venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install "danishrecon[all]"
```
If PowerShell refuses to run `Activate.ps1`, run once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
Every new terminal: run the `Activate.ps1` line again before using `danishrecon`.

**3. nmap (required)**
Download the installer from https://nmap.org/download.html#windows and keep the
**Npcap** option ticked (nmap needs it). Reopen PowerShell and check `nmap --version`.
(`winget install Insecure.Nmap` also works but currently installs an older 7.80.)

**4. The scanning tools, in one command**
```powershell
danishrecon setup
```
This downloads nuclei, katana, httpx, subfinder, Nikto, the Exploit-DB index and rustscan
from their official releases into `%USERPROFILE%\.danishrecon\tools`. Scans find them there
from any folder - no PATH changes needed.

**5. Perl, for Nikto**
`winget install StrawberryPerl.StrawberryPerl` (or https://strawberryperl.com), then reopen
PowerShell. Strawberry Perl already contains the `XML::Writer` module Nikto needs.

**6. Wireshark, for `danishrecon sniff`** (skip if you don't analyse traffic)
`winget install WiresharkFoundation.Wireshark` or https://www.wireshark.org/download.html .
Keep Npcap ticked. DanishRecon finds `tshark` in the default install folder automatically.

**7. Docker Desktop, for OpenVAS** (optional, heavy)
`winget install Docker.DockerDesktop`, start Docker Desktop, then:
```powershell
pip install "danishrecon[openvas]"
danishrecon setup openvas
```
The first start downloads the vulnerability feeds and takes 20-30 minutes
(`docker logs -f danishrecon-openvas` to watch). Docker Desktop must be running whenever you
want the OpenVAS stage; otherwise the scan skips it and says why.

**8. Windows Defender** - only if it removes files
Defender sometimes deletes Nikto files or test samples. If `danishrecon setup nikto` reports
that `nikto.pl` is missing, exclude the tools folder (PowerShell **as Administrator**):
```powershell
Add-MpPreference -ExclusionPath "$env:USERPROFILE\.danishrecon\tools"
```
Keep malware samples you want to analyse in a separate excluded folder too, and never run them.

**9. Admin rights - only for two features**
nmap OS detection (`--os-detect`, the GUI's "OS detection" box) and live capture
(`sniff --live`) need an **Administrator** terminal. Everything else runs as a normal user.

---

## Linux (Debian / Ubuntu / Kali)

```bash
# 1-3, 5, 6: system packages
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nmap perl libxml-writer-perl \
                    libnet-ssleay-perl libio-socket-ssl-perl tshark

# 2: DanishRecon
python3 -m venv ~/danishrecon-venv
source ~/danishrecon-venv/bin/activate
pip install --upgrade pip
pip install "danishrecon[all]"

# 4: scanning tools into ~/.danishrecon/tools
danishrecon setup
```
- Kali already ships `nikto`; DanishRecon will use it.
- `tshark` asks whether non-root users may capture: answer **Yes**, then
  `sudo usermod -aG wireshark $USER` and log out/in. Needed only for `sniff --live`.
- OS detection needs root: `sudo -E env "PATH=$PATH" danishrecon scan ... --os-detect`.
- GUI error *"could not load the Qt platform plugin xcb"*:
  `sudo apt install -y libxcb-cursor0 libxkbcommon-x11-0 libxcb-xinerama0`.
- OpenVAS: install Docker (`sudo apt install docker.io docker-compose-v2`), add yourself to the
  `docker` group, then `pip install "danishrecon[openvas]"` and `danishrecon setup openvas`.

## macOS

```bash
brew install python nmap wireshark perl
cpan XML::Writer                       # Perl module Nikto needs
python3 -m venv ~/danishrecon-venv
source ~/danishrecon-venv/bin/activate
pip install "danishrecon[all]"
danishrecon setup
```
OS detection and live capture need `sudo`. For OpenVAS install Docker Desktop for Mac.

---

## Optional configuration (`.env`)

Nothing here is required. Create a file named `.env` in the folder you run scans from:

```ini
# Higher NVD rate limit (free key: https://nvd.nist.gov/developers/request-an-api-key)
NVD_API_KEY=
# Gemini AI explanations - only used with --ai (sends finding summaries to Google)
GEMINI_API_KEY=
# OpenVAS login, if you changed the default
GVM_USER=admin
GVM_PASSWORD=admin
```

Other environment variables: `DANISHRECON_TOOLS` (tools folder),
`DANISHRECON_RESULTS` (where results go), `NIKTO_PATH`, `EXPLOITDB_PATH`.

---

## Check that everything is ready

```bash
danishrecon-preflight          # green = installed, with a fix hint for anything missing
danishrecon setup --list       # where each scanning tool was found
```
You want `[READY]` from preflight. "Optional" items may stay missing.

## First scan - safely

Only scan what you own or are allowed to test. A safe local target is OWASP Juice Shop
(needs Docker):
```bash
docker run -d --name juice -p 127.0.0.1:3000:3000 bkimminich/juice-shop
danishrecon scan http://127.0.0.1:3000 --i-am-authorized --profile Quick
docker rm -f juice
```
Results land in `./results/` (open `report_<id>.html`). A Quick scan takes a few minutes;
`--profile Full` and `--nuclei` take much longer.

---

## Before every scan - checklist

- [ ] You have **written permission** for the target (or you own it).
- [ ] The virtual environment is active (`danishrecon --help` works).
- [ ] You are in the folder where you want `results/`, or you pass `--output-dir`.
- [ ] Internet access for CVE lookups - or add `--no-nvd` to stay offline.
- [ ] Docker Desktop is running *if* you want the OpenVAS stage.
- [ ] Administrator / sudo terminal *only if* you use OS detection or `sniff --live`.
- [ ] Logged-in areas: pass `--cookie "session=..."` (form logins with CSRF or MFA need the cookie).

## If a scan says ...

| Message in the log | Fix |
|---|---|
| `Nikto not installed - Nikto stage skipped` | `danishrecon setup nikto`, and install Perl (step 5) |
| `Required module not found: XML::Writer` | Windows: use Strawberry Perl. Linux: `sudo apt install libxml-writer-perl`. macOS: `cpan XML::Writer` |
| `nuclei not found - DAST skipped` / `katana not found` | `danishrecon setup nuclei katana` |
| `Exploit-DB index not installed` | `danishrecon setup exploitdb` |
| `OpenVAS not available - ... Docker is not running` | start Docker Desktop (step 7) |
| `OpenVAS not available - the GMP client is not installed` | `pip install "danishrecon[openvas]"` |
| `OS detection needs elevated privileges` | run the terminal as Administrator / with sudo, or untick OS detection |
| `nmap blocked: non-ethernet adapter (VPN/WARP active)` | nothing to do - DanishRecon falls back to a TCP connect scan automatically |
| `Capture failed` (`sniff --live`) | install Npcap (comes with Wireshark/nmap) and use an Administrator terminal |
| GUI button says `START SCAN (missing tools)` | nmap is missing or not on PATH (step 3), then restart the GUI |
| `danishrecon: command not found` | activate the virtual environment (step 2) |
| `setup` download fails behind a company proxy | set `HTTPS_PROXY`, or install the tool manually and set `NIKTO_PATH` / put binaries in `~/.danishrecon/tools/bin` |

## No-setup alternative: Docker

The repository's `Dockerfile` bakes in nmap, nuclei, katana, httpx, subfinder, Nikto, tshark,
rustscan and the Exploit-DB index:

```bash
git clone https://github.com/DanishDhanjal15/DanishRecon-Main
cd DanishRecon-Main
docker build -t danishrecon .
docker run --rm -v "$PWD/out:/data" danishrecon scan example.com --i-am-authorized
```
The container runs the CLI only (no GUI). Reports appear in `./out/results/`.
