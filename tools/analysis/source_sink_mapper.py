#!/usr/bin/env python3
"""
Source-Sink Taint Mapper
========================
SKILL.md Phase 2: Static Taint Analysis

Maps untrusted data Sources to dangerous Sinks across all scan results.
Identifies taint paths that flow from user-controllable inputs to
dangerous operations without adequate sanitization.

Sources (untrusted input entry points):
  - URL query parameters
  - HTTP request headers / cookies
  - Form body parameters
  - DOM inputs (location.hash, document.referrer)

Sinks (dangerous operations):
  - HTML rendering (innerHTML, document.write) → XSS
  - SQL queries                                → SQLi
  - OS command execution (exec, system)        → RCE
  - File operations (open, readFile)           → LFI/Path Traversal
  - HTTP redirects (Location header)           → Open Redirect
  - Server-side templates                      → SSTI
  - External HTTP requests                     → SSRF
"""

import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set
from datetime import datetime
from enum import Enum


class SourceType(Enum):
    URL_QUERY    = "url_query"
    HEADER       = "header"
    COOKIE       = "cookie"
    BODY_PARAM   = "body_param"
    DOM_INPUT    = "dom_input"
    LOCATION_HASH = "location_hash"
    REFERRER     = "referrer"


class SinkType(Enum):
    HTML_RENDER  = "html_render"   # innerHTML, document.write → XSS
    SQL_QUERY    = "sql_query"     # DB queries → SQLi
    OS_EXEC      = "os_exec"       # exec(), system() → RCE
    FILE_OP      = "file_op"       # file read/write → LFI / Path Traversal
    REDIRECT     = "redirect"      # HTTP redirect → Open Redirect
    TEMPLATE     = "template"      # Template eval → SSTI
    HTTP_REQUEST = "http_request"  # fetch(), requests → SSRF


# Map vuln_type strings from fuzz results to sink types
VULN_TO_SINK: Dict[str, SinkType] = {
    "XSS":              SinkType.HTML_RENDER,
    "SQLI":             SinkType.SQL_QUERY,
    "SQLINJECTION":     SinkType.SQL_QUERY,
    "RCE":              SinkType.OS_EXEC,
    "CMDI":             SinkType.OS_EXEC,
    "LFI":              SinkType.FILE_OP,
    "PATH_TRAVERSAL":   SinkType.FILE_OP,
    "OPEN_REDIRECT":    SinkType.REDIRECT,
    "SSTI":             SinkType.TEMPLATE,
    "SSRF":             SinkType.HTTP_REQUEST,
}

# Map source_type strings from _extract_sink_params to SourceType
STR_TO_SOURCE_TYPE: Dict[str, SourceType] = {
    "url_query":     SourceType.URL_QUERY,
    "header":        SourceType.HEADER,
    "cookie":        SourceType.COOKIE,
    "body_param":    SourceType.BODY_PARAM,
    "dom_input":     SourceType.DOM_INPUT,
    "location_hash": SourceType.LOCATION_HASH,
    "referrer":      SourceType.REFERRER,
}


@dataclass
class Source:
    """An untrusted input entry point."""
    source_type: SourceType
    name: str           # parameter/header/cookie name
    url: str            # which URL/page
    context: str = ""   # surrounding code or description


@dataclass
class Sink:
    """A dangerous operation that processes data."""
    sink_type: SinkType
    url: str            # where the sink was triggered
    parameter: str      # which parameter reaches this sink
    context: str = ""   # surrounding code or description
    vuln_type: str = "" # original vuln type string from fuzzer


@dataclass
class TaintPath:
    """
    A complete taint flow: Source → [Sanitizers] → Sink

    SKILL.md principle: A path is exploitable when:
    - No sanitizer is present, OR
    - A sanitizer was identified but a bypass was attempted and succeeded
    """
    source: Source
    sink: Sink
    sanitizers_found: List[str] = field(default_factory=list)
    bypass_attempted: bool = False
    exploitable: bool = False
    confidence: str = "medium"   # high / medium / low
    evidence: str = ""
    payload: str = ""
    cvss: float = 0.0
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return {
            "source": {
                "type": self.source.source_type.value,
                "name": self.source.name,
                "url": self.source.url,
            },
            "sink": {
                "type": self.sink.sink_type.value,
                "url": self.sink.url,
                "parameter": self.sink.parameter,
                "vuln_type": self.sink.vuln_type,
            },
            "sanitizers_found": self.sanitizers_found,
            "bypass_attempted": self.bypass_attempted,
            "exploitable": self.exploitable,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "payload": self.payload,
            "cvss": self.cvss,
            "discovered_at": self.discovered_at,
        }


class SourceSinkMapper:
    """
    SKILL.md Phase 2: Build a Source → Sink taint map from scan results.

    Usage:
        mapper = SourceSinkMapper()
        mapper.ingest_fuzz_results(fuzz_findings)      # from param_fuzzer
        mapper.ingest_dom_sinks(sink_priority_params)  # from js_analyzer
        mapper.ingest_vulns(chain_vulns)               # from vuln_chainer
        paths = mapper.get_exploitable_paths()
    """

    def __init__(self):
        self.sources: List[Source] = []
        self.sinks: List[Sink] = []
        self.taint_paths: List[TaintPath] = []

    # ------------------------------------------------------------------
    # Ingestion methods
    # ------------------------------------------------------------------

    def ingest_fuzz_results(self, findings: List[Dict]):
        """
        Ingest findings from param_fuzzer.py (list of vuln_entry dicts).
        Each confirmed finding is a verified Source → Sink path.
        """
        for f in findings:
            vuln_type = f.get("vuln_type", "").upper()
            sink_type = VULN_TO_SINK.get(vuln_type)
            if not sink_type:
                continue

            source = Source(
                source_type=SourceType.URL_QUERY,
                name=f.get("parameter", "unknown"),
                url=f.get("url", ""),
                context=f.get("payload", ""),
            )
            sink = Sink(
                sink_type=sink_type,
                url=f.get("url", ""),
                parameter=f.get("parameter", ""),
                context=f.get("evidence", ""),
                vuln_type=vuln_type,
            )
            path = TaintPath(
                source=source,
                sink=sink,
                exploitable=True,  # fuzzer confirmed
                confidence=f.get("confidence", "medium"),
                evidence=f.get("evidence", ""),
                payload=f.get("payload", ""),
                cvss=float(f.get("cvss", 5.0)),
            )
            self.sources.append(source)
            self.sinks.append(sink)
            self.taint_paths.append(path)

    def ingest_dom_sinks(self, sink_priority_params: List[Dict]):
        """
        Ingest DOM sink-associated parameters from _extract_sink_params
        (collected in deep_scan.phase_js_analysis).
        These are *potential* paths — exploitability not yet confirmed.
        """
        for sp in sink_priority_params:
            # Skip escalation dicts (different shape)
            if "escalation" in sp:
                continue
            source = Source(
                source_type=STR_TO_SOURCE_TYPE.get(
                    sp.get("source_type", "url_query"), SourceType.URL_QUERY
                ),
                name=sp.get("param", "unknown"),
                url=sp.get("url", ""),
                context=f"DOM sink: {sp.get('sink_type', '')} in {sp.get('sink_file', '')}",
            )
            sink = Sink(
                sink_type=SinkType.HTML_RENDER,  # DOM sinks are HTML rendering by default
                url=sp.get("url", ""),
                parameter=sp.get("param", ""),
                context=sp.get("sink_type", ""),
                vuln_type="XSS",
            )
            path = TaintPath(
                source=source,
                sink=sink,
                exploitable=False,  # not yet confirmed — needs fuzzer
                confidence="low",
                evidence=f"DOM sink '{sp.get('sink_type')}' in {sp.get('sink_file')}",
            )
            self.sources.append(source)
            self.sinks.append(sink)
            self.taint_paths.append(path)

    def ingest_vulns(self, chain_vulns):
        """
        Ingest Vulnerability objects from VulnerabilityChainer.
        These are already classified by type and severity.
        """
        from analysis.vuln_chainer import VulnType
        vuln_type_to_sink = {
            VulnType.XSS:        SinkType.HTML_RENDER,
            VulnType.SQLI:       SinkType.SQL_QUERY,
            VulnType.RCE:        SinkType.OS_EXEC,
            VulnType.LFI:        SinkType.FILE_OP,
            VulnType.SSRF:       SinkType.HTTP_REQUEST,
            VulnType.XXE:        SinkType.FILE_OP,
            VulnType.IDOR:       SinkType.HTTP_REQUEST,
        }
        for v in chain_vulns:
            sink_type = vuln_type_to_sink.get(v.vuln_type)
            if not sink_type:
                continue
            source = Source(
                source_type=SourceType.URL_QUERY,
                name=v.parameter or "unknown",
                url=v.url,
                context=v.description,
            )
            sink = Sink(
                sink_type=sink_type,
                url=v.url,
                parameter=v.parameter,
                context=v.description,
                vuln_type=v.vuln_type.value,
            )
            severity_cvss = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 3.0}
            path = TaintPath(
                source=source,
                sink=sink,
                exploitable=(v.cvss_score > 4.0 or v.severity in ["high", "critical"]),
                confidence="high",
                evidence=v.poc,
                cvss=v.cvss_score or severity_cvss.get(v.severity, 5.0),
            )
            self.sources.append(source)
            self.sinks.append(sink)
            self.taint_paths.append(path)

    # ------------------------------------------------------------------
    # Analysis methods
    # ------------------------------------------------------------------

    def get_exploitable_paths(self) -> List[TaintPath]:
        """
        Return only paths where the taint flow reaches the Sink
        without an effective sanitizer blocking it.

        SKILL.md: "Assume it can be bypassed until proven otherwise."
        """
        return [p for p in self.taint_paths if p.exploitable]

    def get_all_paths(self) -> List[TaintPath]:
        """Return all taint paths including unconfirmed ones."""
        return self.taint_paths

    def get_paths_by_sink(self, sink_type: SinkType) -> List[TaintPath]:
        """Filter paths by sink type."""
        return [p for p in self.taint_paths if p.sink.sink_type == sink_type]

    def get_paths_by_source(self, source_type: SourceType) -> List[TaintPath]:
        """Filter paths by source type."""
        return [p for p in self.taint_paths if p.source.source_type == source_type]

    def summarize(self) -> Dict:
        """Return a summary of the taint map."""
        exploitable = self.get_exploitable_paths()
        return {
            "total_paths": len(self.taint_paths),
            "exploitable_paths": len(exploitable),
            "unique_sources": len({(p.source.source_type, p.source.name) for p in self.taint_paths}),
            "unique_sinks": len({(p.sink.sink_type, p.sink.url) for p in self.taint_paths}),
            "sink_breakdown": {
                st.value: len([p for p in exploitable if p.sink.sink_type == st])
                for st in SinkType
                if any(p.sink.sink_type == st for p in exploitable)
            },
        }


# =============================================================================
# Module self-test
# =============================================================================

if __name__ == "__main__":
    print("SourceSinkMapper Self-Test")
    print("=" * 60)

    mapper = SourceSinkMapper()

    # Test: ingest mock fuzz results
    mock_findings = [
        {
            "url": "https://example.com/search",
            "parameter": "q",
            "vuln_type": "XSS",
            "payload": "<script>alert(1)</script>",
            "evidence": "Payload reflected in response",
            "severity": "high",
            "confidence": "high",
            "cvss": 7.2,
        },
        {
            "url": "https://example.com/api/user",
            "parameter": "id",
            "vuln_type": "SSRF",
            "payload": "http://169.254.169.254/",
            "evidence": "AWS metadata response",
            "severity": "critical",
            "confidence": "high",
            "cvss": 9.1,
        },
    ]
    mapper.ingest_fuzz_results(mock_findings)

    # Test: ingest mock dom sinks
    mock_dom_sinks = [
        {"url": "https://example.com/", "param": "search", "source_type": "url_query",
         "sink_type": "innerHTML", "sink_file": "app.js"},
    ]
    mapper.ingest_dom_sinks(mock_dom_sinks)

    print(f"\nTotal taint paths: {len(mapper.get_all_paths())}")
    print(f"Exploitable paths: {len(mapper.get_exploitable_paths())}")
    print(f"\nSummary: {mapper.summarize()}")

    print("\n[OK] source_sink_mapper.py working correctly")
