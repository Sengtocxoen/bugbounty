#!/usr/bin/env python3
"""
Deep Web Analysis Module
=========================
Comprehensive web analysis combining reNgine + reconftw capabilities.

Phases:
  1. HTTP probing (httpx with full metadata)
  2. Screenshot capture (gowitness/nuclei)
  3. CMS detection (CMSeeK, WPScan)
  4. Virtual host fuzzing (ffuf)
  5. URL collection (waybackurls, gau, katana, gospider, hakrawler)
  6. JavaScript deep analysis (subjs, jsluice, xnLinkFinder, sourcemaps)
  7. Favicon hash analysis (fav-up)
  8. Parameter discovery (arjun, x8)
  9. WebSocket detection
  10. gRPC reflection
  11. Directory/file fuzzing (ffuf, IIS shortnames)
  12. CDN detection (cdncheck)
  13. WAF detection (wafw00f)
"""

import subprocess
import shutil
import json
import re
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except (ImportError, AttributeError):
    requests = None


@dataclass
class WebTarget:
    """A single web target with all discovered information."""
    url: str
    ip: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    cdn: Optional[str] = None
    waf: Optional[str] = None
    cms: Optional[str] = None
    screenshot_path: Optional[str] = None
    urls: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)
    directories: List[str] = field(default_factory=list)
    vhosts: List[str] = field(default_factory=list)
    websocket: bool = False
    grpc: bool = False


@dataclass
class WebAnalysisResult:
    """Complete web analysis results."""
    target: str
    targets: Dict[str, WebTarget] = field(default_factory=dict)
    all_urls: Set[str] = field(default_factory=set)
    all_params: Set[str] = field(default_factory=set)
    all_secrets: List[Dict] = field(default_factory=list)
    all_directories: Set[str] = field(default_factory=set)
    classified_urls: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "total_live_hosts": len(self.targets),
            "total_urls": len(self.all_urls),
            "total_params": len(self.all_params),
            "total_secrets": len(self.all_secrets),
            "total_directories": len(self.all_directories),
            "classified_urls": {k: len(v) for k, v in self.classified_urls.items()},
            "targets": {
                url: {
                    "ip": t.ip, "status": t.status_code, "title": t.title,
                    "server": t.server, "tech": t.technologies, "cdn": t.cdn,
                    "waf": t.waf, "cms": t.cms,
                    "urls_count": len(t.urls), "js_count": len(t.js_files),
                    "params": t.parameters, "secrets_count": len(t.secrets),
                    "dirs_count": len(t.directories), "vhosts": t.vhosts,
                    "websocket": t.websocket, "grpc": t.grpc,
                }
                for url, t in self.targets.items()
            },
            "secrets": self.all_secrets,
        }


def _available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: List[str], timeout: int = 600, stdin_data: str = None) -> Optional[str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            input=stdin_data
        )
        return r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _lines(output: Optional[str]) -> List[str]:
    if not output:
        return []
    return [l.strip() for l in output.splitlines() if l.strip()]


class WebDeepAnalyzer:
    """Deep web analysis engine."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.web_cfg = self.config.get("web_analysis", {})
        self.host_cfg = self.config.get("host_analysis", {})
        self.wordlists = self.config.get("wordlists", {})
        self.tool_paths = self.config.get("tool_paths", {})
        self.perf = self.config.get("performance", {})

    def _tool(self, name: str) -> str:
        return self.tool_paths.get(name, name)

    def run(self, target: str, subdomains: List[str],
            output_dir: Path = None) -> WebAnalysisResult:
        """Run all web analysis phases on discovered subdomains."""
        result = WebAnalysisResult(target=target)
        print(f"\n[WEB] Deep web analysis for {target} ({len(subdomains)} hosts)")

        # Phase 1: HTTP probing
        if self.host_cfg.get("probing", {}).get("enabled", True):
            print("  [*] Phase 1: HTTP probing...")
            self._http_probe(subdomains, result)
            print(f"      Live hosts: {len(result.targets)}")

        live_urls = list(result.targets.keys())
        if not live_urls:
            print("  [-] No live hosts found, skipping web analysis")
            return result

        # Phase 2: CDN detection
        if self.host_cfg.get("cdn_detection", {}).get("enabled", True):
            print("  [*] Phase 2: CDN detection...")
            self._cdn_detection(live_urls, result)

        # Phase 3: WAF detection
        if self.host_cfg.get("waf_detection", {}).get("enabled", True):
            print("  [*] Phase 3: WAF detection...")
            self._waf_detection(live_urls, result)

        # Phase 4: Screenshots
        if self.web_cfg.get("screenshots", {}).get("enabled", True):
            print("  [*] Phase 4: Screenshot capture...")
            self._screenshots(live_urls, result, output_dir)

        # Phase 5: CMS detection
        if self.web_cfg.get("cms_detection", {}).get("enabled", True):
            print("  [*] Phase 5: CMS detection...")
            self._cms_detection(live_urls, result)

        # Phase 6: URL collection
        if self.web_cfg.get("url_collection", {}).get("enabled", True):
            print("  [*] Phase 6: URL collection...")
            self._url_collection(target, live_urls, result)
            print(f"      Total URLs: {len(result.all_urls)}")

        # Phase 7: JavaScript analysis
        if self.web_cfg.get("js_analysis", {}).get("enabled", True):
            print("  [*] Phase 7: JavaScript deep analysis...")
            self._js_analysis(live_urls, result)

        # Phase 8: Parameter discovery
        if self.web_cfg.get("params", {}).get("enabled", True):
            print("  [*] Phase 8: Parameter discovery...")
            self._param_discovery(live_urls, result)
            print(f"      Parameters: {len(result.all_params)}")

        # Phase 9: Virtual host fuzzing
        if self.web_cfg.get("vhost_fuzzing", {}).get("enabled", True):
            print("  [*] Phase 9: Virtual host fuzzing...")
            self._vhost_fuzzing(target, result)

        # Phase 10: Directory fuzzing
        if self.web_cfg.get("fuzzing", {}).get("enabled", True):
            print("  [*] Phase 10: Directory/file fuzzing...")
            self._directory_fuzzing(live_urls, result, output_dir)
            print(f"      Directories: {len(result.all_directories)}")

        # Phase 11: WebSocket detection
        if self.web_cfg.get("websockets", {}).get("enabled", True):
            print("  [*] Phase 11: WebSocket detection...")
            self._websocket_detection(live_urls, result)

        # Phase 12: gRPC reflection
        if self.web_cfg.get("grpc", {}).get("enabled", True):
            print("  [*] Phase 12: gRPC reflection testing...")
            self._grpc_reflection(subdomains, result)

        # Phase 13: Favicon analysis
        if self.web_cfg.get("favicon", {}).get("enabled", True):
            print("  [*] Phase 13: Favicon analysis...")
            self._favicon_analysis(live_urls, result)

        # Phase 14: URL classification
        if self.web_cfg.get("url_collection", {}).get("gf_patterns", {}).get("enabled", True):
            print("  [*] Phase 14: URL classification...")
            self._classify_urls(result)

        if output_dir:
            self._save_results(result, output_dir)

        print(f"[WEB] Complete: {len(result.targets)} hosts, "
              f"{len(result.all_urls)} URLs, "
              f"{len(result.all_secrets)} secrets")
        return result

    # -------------------------------------------------------------------------
    # HTTP Probing
    # -------------------------------------------------------------------------
    def _http_probe(self, subdomains: List[str], result: WebAnalysisResult):
        """Probe subdomains with httpx for live host detection."""
        if not _available("httpx"):
            # Fallback: basic HTTP check
            for sub in subdomains[:100]:
                for scheme in ["https", "http"]:
                    url = f"{scheme}://{sub}"
                    if requests:
                        try:
                            resp = requests.get(url, timeout=10, verify=False)
                            wt = WebTarget(
                                url=url, status_code=resp.status_code,
                                server=resp.headers.get("server"),
                            )
                            result.targets[url] = wt
                            break
                        except Exception:
                            continue
            return

        probe_cfg = self.host_cfg.get("probing", {})
        ports = probe_cfg.get("ports", [80, 443])
        extra = probe_cfg.get("extra_ports", [])
        if probe_cfg.get("uncommon_ports", True):
            ports = list(set(ports + extra))

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tmp:
            for sub in subdomains:
                tmp.write(f"{sub}\n")
            tmp_path = tmp.name

        port_str = ",".join(str(p) for p in ports) if ports else "80,443"
        threads = self.perf.get("threads", {}).get("httpx", 50)

        cmd = [
            self._tool("httpx"), "-l", tmp_path,
            "-p", port_str,
            "-json", "-silent", "-nc",
            "-threads", str(threads),
            "-title", "-status-code", "-tech-detect",
            "-server", "-ip", "-cname", "-cdn",
            "-content-length", "-follow-redirects",
            "-tls-grab",
        ]

        output = _run(cmd, timeout=900)
        for line in _lines(output):
            try:
                data = json.loads(line)
                url = data.get("url", "")
                if not url:
                    continue
                wt = WebTarget(
                    url=url,
                    ip=data.get("host", data.get("a", [None])[0] if isinstance(data.get("a"), list) else data.get("a")),
                    status_code=data.get("status_code"),
                    title=data.get("title"),
                    server=data.get("webserver"),
                    technologies=data.get("tech", []),
                    cdn=data.get("cdn_name"),
                )
                result.targets[url] = wt
            except (json.JSONDecodeError, TypeError, IndexError):
                continue

    # -------------------------------------------------------------------------
    # CDN Detection
    # -------------------------------------------------------------------------
    def _cdn_detection(self, urls: List[str], result: WebAnalysisResult):
        if not _available("cdncheck"):
            return

        hosts = set()
        for url in urls:
            host = re.sub(r'https?://', '', url).split('/')[0].split(':')[0]
            hosts.add(host)

        input_data = "\n".join(hosts)
        output = _run(
            [self._tool("cdncheck"), "-silent", "-json"],
            timeout=120, stdin_data=input_data
        )
        for line in _lines(output):
            try:
                data = json.loads(line)
                ip = data.get("ip", "")
                cdn = data.get("cdn_name", "")
                if cdn:
                    for url, wt in result.targets.items():
                        if wt.ip == ip:
                            wt.cdn = cdn
            except json.JSONDecodeError:
                continue

    # -------------------------------------------------------------------------
    # WAF Detection
    # -------------------------------------------------------------------------
    def _waf_detection(self, urls: List[str], result: WebAnalysisResult):
        if not _available("wafw00f"):
            return

        for url in urls[:50]:  # Limit to avoid slowness
            output = _run(
                ["wafw00f", url, "-o", "-"], timeout=30
            )
            if output:
                # Parse wafw00f output
                for line in output.splitlines():
                    if "is behind" in line.lower():
                        waf_match = re.search(r'is behind (.+?)(?:\s|$)', line, re.I)
                        if waf_match and url in result.targets:
                            result.targets[url].waf = waf_match.group(1).strip()

    # -------------------------------------------------------------------------
    # Screenshots
    # -------------------------------------------------------------------------
    def _screenshots(self, urls: List[str], result: WebAnalysisResult,
                     output_dir: Path = None):
        if not output_dir:
            return

        ss_dir = output_dir / "screenshots"
        ss_dir.mkdir(parents=True, exist_ok=True)

        if _available("gowitness"):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                for url in urls:
                    tmp.write(f"{url}\n")
                tmp_path = tmp.name

            _run([
                self._tool("gowitness"), "file", "-f", tmp_path,
                "-P", str(ss_dir), "--timeout", "15",
            ], timeout=600)
        elif _available("nuclei"):
            # Nuclei headless screenshots
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                for url in urls:
                    tmp.write(f"{url}\n")
                tmp_path = tmp.name

            _run([
                self._tool("nuclei"), "-l", tmp_path,
                "-headless", "-t", "headless/screenshot.yaml",
                "-silent",
            ], timeout=600)

    # -------------------------------------------------------------------------
    # CMS Detection
    # -------------------------------------------------------------------------
    def _cms_detection(self, urls: List[str], result: WebAnalysisResult):
        cms_cfg = self.web_cfg.get("cms_detection", {})

        # CMSeeK
        cmseek_path = shutil.which("cmseek") or f"{Path.home()}/Tools/CMSeeK/cmseek.py"
        for url in urls[:30]:
            if Path(cmseek_path).exists() or _available("cmseek"):
                output = _run([
                    "python3", cmseek_path, "-u", url, "--batch"
                ], timeout=60)
                if output:
                    for line in output.splitlines():
                        if "CMS:" in line or "Detected CMS:" in line:
                            cms = line.split(":")[-1].strip()
                            if url in result.targets:
                                result.targets[url].cms = cms
                            break

            # If WordPress detected, run WPScan
            if (url in result.targets and result.targets[url].cms
                    and "wordpress" in result.targets[url].cms.lower()
                    and cms_cfg.get("wpscan_on_wordpress", True)
                    and _available("wpscan")):
                wp_token = cms_cfg.get("wpscan_api_token")
                cmd = ["wpscan", "--url", url, "--enumerate", "vp,vt,u"]
                if wp_token:
                    cmd.extend(["--api-token", wp_token])
                _run(cmd, timeout=300)

    # -------------------------------------------------------------------------
    # URL Collection
    # -------------------------------------------------------------------------
    def _url_collection(self, target: str, urls: List[str],
                        result: WebAnalysisResult):
        url_cfg = self.web_cfg.get("url_collection", {})
        collected = set()

        # Passive URL collection
        passive_tools = []
        if url_cfg.get("waybackurls", True) and _available("waybackurls"):
            passive_tools.append(("waybackurls", [
                self._tool("waybackurls"), target
            ]))
        if url_cfg.get("gau", True) and _available("gau"):
            passive_tools.append(("gau", [
                self._tool("gau"), target, "--threads", "10"
            ]))

        with ThreadPoolExecutor(max_workers=max(len(passive_tools), 1)) as pool:
            futures = {}
            for name, cmd in passive_tools:
                futures[pool.submit(_run, cmd, 300)] = name
            for future in as_completed(futures):
                output = future.result()
                for line in _lines(output):
                    if line.startswith("http"):
                        collected.add(line)

        # Active crawling
        active_tools = []
        if url_cfg.get("katana", True) and _available("katana"):
            depth = url_cfg.get("crawl_depth", 5)
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                for u in urls[:20]:
                    tmp.write(f"{u}\n")
                urls_file = tmp.name

            output = _run([
                self._tool("katana"), "-list", urls_file,
                "-d", str(depth), "-silent", "-jc", "-kf", "all",
                "-c", str(self.perf.get("threads", {}).get("katana", 20)),
            ], timeout=600)
            for line in _lines(output):
                if line.startswith("http"):
                    collected.add(line)

        if url_cfg.get("gospider", True) and _available("gospider"):
            for u in urls[:10]:
                output = _run([
                    self._tool("gospider"), "-s", u,
                    "-d", "3", "-c", "10", "--subs",
                    "-t", str(self.perf.get("threads", {}).get("gospider", 20)),
                ], timeout=300)
                for line in _lines(output):
                    url_match = re.search(r'(https?://[^\s]+)', line)
                    if url_match:
                        collected.add(url_match.group(1))

        if url_cfg.get("hakrawler", True) and _available("hakrawler"):
            for u in urls[:10]:
                output = _run([
                    self._tool("hakrawler"), "-url", u, "-depth", "3", "-subs",
                ], timeout=120)
                for line in _lines(output):
                    if line.startswith("http"):
                        collected.add(line)

        # Limit
        max_urls = url_cfg.get("max_urls", 50000)
        result.all_urls = set(list(collected)[:max_urls])

        # Assign URLs to targets
        for url in result.all_urls:
            for tgt_url, wt in result.targets.items():
                host = re.sub(r'https?://', '', tgt_url).split('/')[0].split(':')[0]
                if host in url:
                    wt.urls.append(url)
                    break

    # -------------------------------------------------------------------------
    # JavaScript Analysis
    # -------------------------------------------------------------------------
    def _js_analysis(self, urls: List[str], result: WebAnalysisResult):
        js_cfg = self.web_cfg.get("js_analysis", {})

        # Discover JS files with subjs
        if js_cfg.get("subjs", True) and _available("subjs"):
            input_data = "\n".join(urls)
            output = _run(
                [self._tool("subjs")],
                timeout=300, stdin_data=input_data
            )
            for line in _lines(output):
                if line.endswith(".js") or ".js?" in line:
                    for tgt_url, wt in result.targets.items():
                        host = re.sub(r'https?://', '', tgt_url).split('/')[0]
                        if host in line:
                            wt.js_files.append(line)
                            break

        # Extract secrets and endpoints from JS with jsluice
        if js_cfg.get("jsluice", True) and _available("jsluice"):
            for tgt_url, wt in result.targets.items():
                for js_url in wt.js_files[:50]:
                    if requests:
                        try:
                            resp = requests.get(js_url, timeout=15, verify=False)
                            if resp.status_code == 200:
                                output = _run(
                                    ["jsluice", "urls"],
                                    timeout=30, stdin_data=resp.text
                                )
                                for line in _lines(output):
                                    try:
                                        data = json.loads(line)
                                        endpoint = data.get("url", "")
                                        if endpoint:
                                            wt.endpoints.append(endpoint)
                                    except json.JSONDecodeError:
                                        if line.startswith("/") or line.startswith("http"):
                                            wt.endpoints.append(line)

                                # Check for secrets
                                output = _run(
                                    ["jsluice", "secrets"],
                                    timeout=30, stdin_data=resp.text
                                )
                                for line in _lines(output):
                                    try:
                                        secret = json.loads(line)
                                        if secret:
                                            wt.secrets.append(secret)
                                            result.all_secrets.append({
                                                "source": js_url,
                                                **secret
                                            })
                                    except json.JSONDecodeError:
                                        pass
                        except Exception:
                            continue

        # xnLinkFinder
        if js_cfg.get("xnlinkfinder", True) and _available("xnLinkFinder"):
            for tgt_url in list(result.targets.keys())[:10]:
                output = _run([
                    "xnLinkFinder", "-i", tgt_url,
                    "-d", "2", "-sf", result.target,
                ], timeout=120)
                for line in _lines(output):
                    if line.startswith("http") or line.startswith("/"):
                        result.all_urls.add(line)

        # Source maps
        if js_cfg.get("sourcemaps", {}).get("enabled", True) and _available("sourcemapper"):
            for tgt_url, wt in result.targets.items():
                for js_url in wt.js_files[:20]:
                    map_url = js_url + ".map"
                    if requests:
                        try:
                            resp = requests.head(map_url, timeout=10, verify=False)
                            if resp.status_code == 200:
                                result.all_secrets.append({
                                    "type": "source_map",
                                    "url": map_url,
                                    "severity": "medium",
                                })
                        except Exception:
                            continue

    # -------------------------------------------------------------------------
    # Parameter Discovery
    # -------------------------------------------------------------------------
    def _param_discovery(self, urls: List[str], result: WebAnalysisResult):
        params_cfg = self.web_cfg.get("params", {})

        # Mine from collected URLs first
        if params_cfg.get("mine_from_urls", True):
            for url in result.all_urls:
                # Extract query parameters
                if "?" in url:
                    query = url.split("?", 1)[1]
                    for param in query.split("&"):
                        name = param.split("=")[0]
                        if name:
                            result.all_params.add(name)

        # Arjun for hidden parameter discovery
        if params_cfg.get("tool", "arjun") == "arjun" and _available("arjun"):
            for url in urls[:15]:
                output = _run([
                    self._tool("arjun"), "-u", url,
                    "-t", str(self.perf.get("threads", {}).get("arjun", 20)),
                    "-oJ", "-",
                ], timeout=120)
                if output:
                    try:
                        data = json.loads(output)
                        for endpoint, params in data.items():
                            for param in params:
                                result.all_params.add(param)
                                # Add to target
                                for tgt_url, wt in result.targets.items():
                                    if re.sub(r'https?://', '', tgt_url).split('/')[0] in endpoint:
                                        wt.parameters.append(param)
                                        break
                    except json.JSONDecodeError:
                        pass

    # -------------------------------------------------------------------------
    # Virtual Host Fuzzing
    # -------------------------------------------------------------------------
    def _vhost_fuzzing(self, target: str, result: WebAnalysisResult):
        if not _available("ffuf"):
            return

        vhost_cfg = self.web_cfg.get("vhost_fuzzing", {})
        wordlist = vhost_cfg.get(
            "wordlist",
            self.wordlists.get("vhosts",
                               "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt")
        )
        if not Path(wordlist).exists():
            return

        # Pick first live IP
        target_url = None
        for url, wt in result.targets.items():
            if wt.ip:
                target_url = url
                break
        if not target_url:
            return

        output = _run([
            self._tool("ffuf"), "-u", target_url,
            "-H", f"Host: FUZZ.{target}",
            "-w", wordlist,
            "-ac",  # auto-calibrate
            "-mc", "200,301,302,403",
            "-s",   # silent
            "-json",
        ], timeout=300)

        for line in _lines(output):
            try:
                data = json.loads(line)
                vhost = data.get("input", {}).get("FUZZ", "")
                if vhost:
                    full = f"{vhost}.{target}"
                    for url, wt in result.targets.items():
                        wt.vhosts.append(full)
                        break
            except json.JSONDecodeError:
                continue

    # -------------------------------------------------------------------------
    # Directory Fuzzing
    # -------------------------------------------------------------------------
    def _directory_fuzzing(self, urls: List[str], result: WebAnalysisResult,
                           output_dir: Path = None):
        fuzz_cfg = self.web_cfg.get("fuzzing", {})
        wordlist = fuzz_cfg.get(
            "wordlist",
            self.wordlists.get("directories",
                               "/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt")
        )
        if not Path(wordlist).exists():
            return

        extensions = fuzz_cfg.get("extensions", ["php", "asp", "aspx", "jsp", "html"])
        ext_str = ",".join(extensions)
        rate = fuzz_cfg.get("rate", 150)
        timeout_sec = fuzz_cfg.get("timeout", 900)

        for url in urls[:20]:
            if not _available("ffuf"):
                break

            fuzz_url = url.rstrip("/") + "/FUZZ"
            cmd = [
                self._tool("ffuf"),
                "-u", fuzz_url,
                "-w", wordlist,
                "-mc", "200,201,204,301,302,307,401,403,405",
                "-ac",  # Auto-calibrate for soft-404
                "-rate", str(rate),
                "-s",   # Silent
                "-json",
                "-recursion" if fuzz_cfg.get("recursive", True) else "",
                "-recursion-depth", str(fuzz_cfg.get("max_depth", 3)),
                "-e", ext_str,
            ]
            cmd = [c for c in cmd if c]  # Remove empty strings

            output = _run(cmd, timeout=timeout_sec)
            for line in _lines(output):
                try:
                    data = json.loads(line)
                    path = data.get("input", {}).get("FUZZ", "")
                    status = data.get("status", 0)
                    if path and status:
                        full_url = url.rstrip("/") + "/" + path
                        result.all_directories.add(full_url)
                        if url in result.targets:
                            result.targets[url].directories.append(full_url)
                except json.JSONDecodeError:
                    continue

        # IIS shortname scanning
        if fuzz_cfg.get("iis_shortnames", {}).get("enabled", True) and _available("shortscan"):
            for url in urls[:10]:
                output = _run([
                    self._tool("shortscan"), url
                ], timeout=120)
                if output and "found" in output.lower():
                    for line in _lines(output):
                        if "~" in line:
                            result.all_directories.add(f"{url}/{line.strip()}")

    # -------------------------------------------------------------------------
    # WebSocket Detection
    # -------------------------------------------------------------------------
    def _websocket_detection(self, urls: List[str], result: WebAnalysisResult):
        if not requests:
            return

        for url in urls[:30]:
            try:
                # Check for WebSocket upgrade
                ws_url = url.replace("https://", "wss://").replace("http://", "ws://")
                resp = requests.get(
                    url, timeout=10, verify=False,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Version": "13",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    }
                )
                if resp.status_code == 101:
                    if url in result.targets:
                        result.targets[url].websocket = True
                # Also check common WS paths
                for path in ["/ws", "/websocket", "/socket.io/", "/cable"]:
                    try:
                        resp = requests.get(
                            url.rstrip("/") + path, timeout=5, verify=False,
                            headers={"Upgrade": "websocket", "Connection": "Upgrade"}
                        )
                        if resp.status_code in [101, 200, 400]:
                            if url in result.targets:
                                result.targets[url].websocket = True
                                break
                    except Exception:
                        continue
            except Exception:
                continue

    # -------------------------------------------------------------------------
    # gRPC Reflection
    # -------------------------------------------------------------------------
    def _grpc_reflection(self, subdomains: List[str], result: WebAnalysisResult):
        if not _available("grpcurl"):
            return

        grpc_cfg = self.web_cfg.get("grpc", {})
        ports = grpc_cfg.get("ports", [50051, 50052, 9090, 443])

        for sub in subdomains[:20]:
            for port in ports:
                output = _run([
                    self._tool("grpcurl"), "-plaintext",
                    f"{sub}:{port}", "list"
                ], timeout=10)
                if output and "grpc.reflection" in output.lower() or (output and not output.startswith("Failed")):
                    # gRPC service found
                    url_key = f"https://{sub}" if f"https://{sub}" in result.targets else f"http://{sub}"
                    if url_key in result.targets:
                        result.targets[url_key].grpc = True
                    result.all_secrets.append({
                        "type": "grpc_reflection",
                        "host": f"{sub}:{port}",
                        "services": output,
                        "severity": "medium",
                    })
                    break

    # -------------------------------------------------------------------------
    # Favicon Analysis
    # -------------------------------------------------------------------------
    def _favicon_analysis(self, urls: List[str], result: WebAnalysisResult):
        """Reveal real IPs behind CDN via favicon hash (fav-up + mmh3)."""
        try:
            import mmh3
            import codecs
        except ImportError:
            return

        if not requests:
            return

        for url in urls[:30]:
            try:
                favicon_url = url.rstrip("/") + "/favicon.ico"
                resp = requests.get(favicon_url, timeout=10, verify=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    # Calculate favicon hash (Shodan-compatible)
                    encoded = codecs.encode(resp.content, "base64")
                    fav_hash = mmh3.hash(encoded)
                    if fav_hash and url in result.targets:
                        result.all_secrets.append({
                            "type": "favicon_hash",
                            "url": favicon_url,
                            "hash": fav_hash,
                            "shodan_query": f"http.favicon.hash:{fav_hash}",
                            "severity": "info",
                        })
            except Exception:
                continue

    # -------------------------------------------------------------------------
    # URL Classification (gf patterns)
    # -------------------------------------------------------------------------
    def _classify_urls(self, result: WebAnalysisResult):
        """Classify collected URLs by vulnerability type using gf patterns."""
        if not _available("gf"):
            return

        gf_cfg = self.web_cfg.get("url_collection", {}).get("gf_patterns", {})
        patterns = gf_cfg.get("patterns", [
            "xss", "sqli", "ssrf", "redirect", "rce", "idor", "ssti", "lfi"
        ])

        # Write all URLs to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tmp:
            for url in result.all_urls:
                tmp.write(f"{url}\n")
            tmp_path = tmp.name

        for pattern in patterns:
            output = _run(
                [self._tool("gf"), pattern],
                timeout=60, stdin_data="\n".join(result.all_urls)
            )
            if output:
                matches = _lines(output)
                if matches:
                    result.classified_urls[pattern] = matches

    # -------------------------------------------------------------------------
    # Save Results
    # -------------------------------------------------------------------------
    def _save_results(self, result: WebAnalysisResult, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)

        # Full results
        with open(output_dir / f"web_analysis_{result.target.replace('.', '_')}.json", "w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)

        # URL list
        with open(output_dir / "all_urls.txt", "w") as f:
            for url in sorted(result.all_urls):
                f.write(f"{url}\n")

        # Parameters
        with open(output_dir / "parameters.txt", "w") as f:
            for p in sorted(result.all_params):
                f.write(f"{p}\n")

        # Classified URLs
        for pattern, urls in result.classified_urls.items():
            with open(output_dir / f"urls_{pattern}.txt", "w") as f:
                for url in urls:
                    f.write(f"{url}\n")

        # Secrets
        if result.all_secrets:
            with open(output_dir / "secrets.json", "w") as f:
                json.dump(result.all_secrets, f, indent=2)

        # Directories
        with open(output_dir / "directories.txt", "w") as f:
            for d in sorted(result.all_directories):
                f.write(f"{d}\n")
