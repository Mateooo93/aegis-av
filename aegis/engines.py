"""
Aegis AV - Detection Engines
Multi-engine malware detection: Hash-based, Heuristic, PE Analysis, YARA.
"""

import os
import hashlib
import math
import struct
import logging
from collections import Counter
from datetime import datetime

from aegis.config import (
    SUSPICIOUS_APIS, SUSPICIOUS_STRINGS, SUSPICIOUS_PATHS,
    EXECUTABLE_EXTENSIONS, RULES_DIR
)

logger = logging.getLogger("Aegis.Engines")

# Try importing optional dependencies
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    logger.warning("pefile not installed - PE analysis disabled")

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    logger.warning("yara-python not installed - YARA scanning disabled")


# ── Utility Functions ──────────────────────────────────────────────

def compute_hashes(file_path):
    """Compute MD5, SHA1, SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except Exception as e:
        logger.debug("Hash computation failed for %s: %s", file_path, e)
        return None


def calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def file_entropy(file_path, max_size=10 * 1024 * 1024):
    """Calculate entropy of a file (up to max_size bytes)."""
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_size)
        return calculate_entropy(data)
    except Exception:
        return 0.0


# ── Detection Result ───────────────────────────────────────────────

class DetectionResult:
    """Represents a detection result from any engine."""

    def __init__(self, detected=False, threat_name="", threat_type="",
                 severity="low", engine="", confidence=0, details=""):
        self.detected = detected
        self.threat_name = threat_name
        self.threat_type = threat_type
        self.severity = severity  # low, medium, high, critical
        self.engine = engine
        self.confidence = confidence  # 0-100
        self.details = details

    def to_dict(self):
        return {
            "detected": self.detected,
            "threat_name": self.threat_name,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "engine": self.engine,
            "confidence": self.confidence,
            "details": self.details,
        }

    def __repr__(self):
        if self.detected:
            return f"Detection({self.threat_name}, {self.severity}, {self.engine})"
        return "Detection(clean)"


# ── Hash Engine ────────────────────────────────────────────────────

class HashEngine:
    """Hash-based detection using known malware hash database."""

    def __init__(self, database):
        self.db = database
        self.name = "HashEngine"
        self._load_seed_hashes()

    def _load_seed_hashes(self):
        """Seed the database with known test malware hashes (EICAR etc.)."""
        # EICAR test file hash
        known = [
            {
                "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "md5": "44d88612fea8a8f36de82e1278abb02f",
                "name": "EICAR.TestFile",
                "severity": "low",
            },
            # Well-known malware sample hashes (these are publicly known)
            {
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "name": "Empty.File.Suspicious",
                "severity": "low",
            },
        ]
        for entry in known:
            self.db.add_malware_hash(
                sha256=entry["sha256"],
                threat_name=entry["name"],
                md5=entry.get("md5", ""),
                severity=entry["severity"],
                source="seed"
            )

    def scan(self, file_path):
        """Scan a file against known malware hashes."""
        hashes = compute_hashes(file_path)
        if not hashes:
            return DetectionResult()

        result = self.db.check_hash(hashes["sha256"])
        if result:
            return DetectionResult(
                detected=True,
                threat_name=result["threat_name"],
                threat_type="known_malware",
                severity=result["severity"],
                engine=self.name,
                confidence=100,
                details=f"SHA256 match: {hashes['sha256']}"
            )

        # Check whitelist
        if self.db.is_whitelisted(file_hash=hashes["sha256"]):
            return DetectionResult(engine=self.name, details="Whitelisted")

        return DetectionResult(engine=self.name)


# ── Heuristic Engine ──────────────────────────────────────────────

class HeuristicEngine:
    """Heuristic-based detection analyzing file characteristics and behaviors."""

    SENSITIVITY_THRESHOLDS = {
        "low": 60,
        "medium": 40,
        "high": 20,
    }

    def __init__(self, sensitivity="medium"):
        self.name = "HeuristicEngine"
        self.sensitivity = sensitivity
        self.threshold = self.SENSITIVITY_THRESHOLDS.get(sensitivity, 40)

    def scan(self, file_path):
        """Perform heuristic analysis on a file."""
        score = 0
        findings = []

        try:
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            file_name = os.path.basename(file_path)
        except Exception:
            return DetectionResult(engine=self.name)

        # ── Check 1: Double extension (e.g., document.pdf.exe) ─────
        parts = file_name.split(".")
        if len(parts) > 2:
            exts = [f".{p.lower()}" for p in parts[1:]]
            if any(e in EXECUTABLE_EXTENSIONS for e in exts[:-1]):
                score += 30
                findings.append("Double extension detected")
            elif exts[-1] in EXECUTABLE_EXTENSIONS and len(exts) > 1:
                score += 20
                findings.append(f"Multiple extensions: {'.'.join(parts[1:])}")

        # ── Check 2: File in suspicious location ───────────────────
        file_dir = os.path.dirname(file_path).lower()
        for sus_path in SUSPICIOUS_PATHS:
            if file_dir.startswith(sus_path.lower()):
                if file_ext in EXECUTABLE_EXTENSIONS:
                    score += 15
                    findings.append(f"Executable in suspicious location: {sus_path}")
                break

        # ── Check 3: High entropy (potential packing/encryption) ───
        try:
            entropy = file_entropy(file_path)
            if entropy > 7.5:
                score += 25
                findings.append(f"Very high entropy: {entropy:.2f} (potential packing)")
            elif entropy > 7.0:
                score += 15
                findings.append(f"High entropy: {entropy:.2f}")
        except Exception:
            pass

        # ── Check 4: Suspicious strings in file ───────────────────
        try:
            with open(file_path, "rb") as f:
                content = f.read(min(file_size, 5 * 1024 * 1024))  # Max 5MB

            sus_string_count = 0
            matched_strings = []
            for pattern in SUSPICIOUS_STRINGS:
                if pattern.lower() in content.lower():
                    sus_string_count += 1
                    try:
                        matched_strings.append(pattern.decode("utf-8", errors="ignore"))
                    except Exception:
                        pass

            if sus_string_count >= 10:
                score += 30
                findings.append(f"Many suspicious strings found ({sus_string_count})")
            elif sus_string_count >= 5:
                score += 20
                findings.append(f"Suspicious strings found ({sus_string_count})")
            elif sus_string_count >= 3:
                score += 10
                findings.append(f"Some suspicious strings ({sus_string_count})")
        except Exception:
            pass

        # ── Check 5: Hidden file ───────────────────────────────────
        try:
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
            if attrs != -1:
                FILE_ATTRIBUTE_HIDDEN = 0x02
                FILE_ATTRIBUTE_SYSTEM = 0x04
                if attrs & FILE_ATTRIBUTE_HIDDEN:
                    score += 10
                    findings.append("File is hidden")
                if attrs & FILE_ATTRIBUTE_SYSTEM:
                    score += 5
                    findings.append("File has system attribute")
        except Exception:
            pass

        # ── Check 6: Recently created executable in user space ─────
        try:
            ctime = os.path.getctime(file_path)
            age_hours = (datetime.now().timestamp() - ctime) / 3600
            if age_hours < 1 and file_ext in EXECUTABLE_EXTENSIONS:
                score += 10
                findings.append("Recently created executable (<1 hour)")
        except Exception:
            pass

        # ── Check 7: Very small executable (potential shellcode) ───
        if file_ext in EXECUTABLE_EXTENSIONS:
            if file_size < 10240:  # < 10KB
                score += 15
                findings.append(f"Very small executable: {file_size} bytes")
            elif file_size < 50 * 1024:  # < 50KB
                score += 5
                findings.append(f"Small executable: {file_size} bytes")

        # ── Check 8: Executable without standard headers ───────────
        if file_ext in EXECUTABLE_EXTENSIONS:
            try:
                with open(file_path, "rb") as f:
                    magic = f.read(2)
                if magic != b"MZ" and file_ext in {".exe", ".dll", ".sys", ".scr"}:
                    score += 20
                    findings.append("Executable without valid MZ header")
            except Exception:
                pass

        # ── Determine result ───────────────────────────────────────
        if score >= self.threshold:
            severity = "low"
            if score >= 60:
                severity = "high"
            elif score >= 40:
                severity = "medium"
            if score >= 80:
                severity = "critical"

            return DetectionResult(
                detected=True,
                threat_name=f"Heuristic.Suspicious.{severity.title()}",
                threat_type="heuristic",
                severity=severity,
                engine=self.name,
                confidence=min(score, 100),
                details="; ".join(findings)
            )

        return DetectionResult(engine=self.name)


# ── PE Analyzer ────────────────────────────────────────────────────

class PEAnalyzer:
    """Portable Executable (PE) file analysis engine."""

    def __init__(self):
        self.name = "PEAnalyzer"
        self.available = HAS_PEFILE

    def scan(self, file_path):
        """Analyze a PE file for suspicious characteristics."""
        if not self.available:
            return DetectionResult(engine=self.name, details="pefile not available")

        # Only analyze PE files
        try:
            with open(file_path, "rb") as f:
                magic = f.read(2)
            if magic != b"MZ":
                return DetectionResult(engine=self.name)
        except Exception:
            return DetectionResult(engine=self.name)

        try:
            pe = pefile.PE(file_path, fast_load=False)
        except Exception:
            return DetectionResult(engine=self.name)

        score = 0
        findings = []

        try:
            # ── Check 1: Section analysis ──────────────────────────
            for section in pe.sections:
                try:
                    name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                except Exception:
                    name = "UNKNOWN"

                # High entropy section
                entropy = section.get_entropy()
                if entropy > 7.0:
                    score += 15
                    findings.append(f"High entropy section '{name}': {entropy:.2f}")

                # Unusual section names
                normal_names = {".text", ".data", ".rdata", ".rsrc", ".reloc",
                                ".idata", ".edata", ".bss", ".tls", ".pdata",
                                ".debug", ".CRT", ".sxdata"}
                if name and name not in normal_names and not name.startswith("."):
                    score += 10
                    findings.append(f"Unusual section name: '{name}'")

                # Executable and writable section
                if (section.Characteristics & 0x20000000 and  # EXECUTE
                    section.Characteristics & 0x80000000):     # WRITE
                    score += 20
                    findings.append(f"Section '{name}' is both executable and writable")

                # Very small or empty code section
                if name == ".text" and section.SizeOfRawData < 512:
                    score += 15
                    findings.append("Very small .text section")

            # ── Check 2: Import analysis ───────────────────────────
            suspicious_imports = set()
            total_imports = 0

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        total_imports += 1
                        if imp.name:
                            imp_name = imp.name.decode("utf-8", errors="ignore")
                            if imp_name in SUSPICIOUS_APIS:
                                suspicious_imports.add(imp_name)

            if len(suspicious_imports) >= 10:
                score += 35
                findings.append(f"Many suspicious API imports ({len(suspicious_imports)}): "
                                f"{', '.join(list(suspicious_imports)[:5])}...")
            elif len(suspicious_imports) >= 5:
                score += 25
                findings.append(f"Suspicious API imports ({len(suspicious_imports)}): "
                                f"{', '.join(list(suspicious_imports)[:5])}")
            elif len(suspicious_imports) >= 3:
                score += 15
                findings.append(f"Some suspicious imports: {', '.join(suspicious_imports)}")

            # Very few imports (potential packed binary)
            if total_imports < 5 and total_imports > 0:
                score += 15
                findings.append(f"Very few imports ({total_imports}) - possible packing")
            elif total_imports == 0:
                score += 20
                findings.append("No imports found - likely packed or shellcode")

            # ── Check 3: Resource analysis ─────────────────────────
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                resource_count = 0
                large_resources = 0
                for rsrc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(rsrc_type, "directory"):
                        for rsrc_id in rsrc_type.directory.entries:
                            resource_count += 1
                            if hasattr(rsrc_id, "directory"):
                                for rsrc_lang in rsrc_id.directory.entries:
                                    if rsrc_lang.data.struct.Size > 500000:
                                        large_resources += 1
                if large_resources > 0:
                    score += 10
                    findings.append(f"Large embedded resources ({large_resources})")

            # ── Check 4: Timestamp analysis ────────────────────────
            try:
                timestamp = pe.FILE_HEADER.TimeDateStamp
                compile_date = datetime.fromtimestamp(timestamp)
                now = datetime.now()

                # Future timestamp
                if compile_date > now:
                    score += 15
                    findings.append(f"Future compile timestamp: {compile_date}")

                # Very old timestamp (before 2000)
                if compile_date.year < 2000:
                    score += 10
                    findings.append(f"Very old compile timestamp: {compile_date.year}")
            except Exception:
                pass

            # ── Check 5: Debug information ─────────────────────────
            has_debug = hasattr(pe, "DIRECTORY_ENTRY_DEBUG")
            if not has_debug:
                score += 5
                findings.append("No debug information")

            # ── Check 6: TLS callbacks ─────────────────────────────
            if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
                tls = pe.DIRECTORY_ENTRY_TLS
                if tls and hasattr(tls.struct, "AddressOfCallBacks"):
                    score += 15
                    findings.append("TLS callbacks present (potential anti-debugging)")

            # ── Check 7: Checksum validation ───────────────────────
            if pe.OPTIONAL_HEADER.CheckSum == 0:
                score += 5
                findings.append("Zero checksum in PE header")
            else:
                calculated = pe.generate_checksum()
                if calculated != pe.OPTIONAL_HEADER.CheckSum:
                    score += 10
                    findings.append("PE checksum mismatch")

            pe.close()

        except Exception as e:
            logger.debug("PE analysis error for %s: %s", file_path, e)
            try:
                pe.close()
            except Exception:
                pass
            return DetectionResult(engine=self.name)

        # ── Determine result ───────────────────────────────────────
        if score >= 30:
            severity = "low"
            if score >= 70:
                severity = "critical"
            elif score >= 50:
                severity = "high"
            elif score >= 35:
                severity = "medium"

            return DetectionResult(
                detected=True,
                threat_name=f"PE.Suspicious.{severity.title()}",
                threat_type="pe_analysis",
                severity=severity,
                engine=self.name,
                confidence=min(score, 100),
                details="; ".join(findings)
            )

        return DetectionResult(engine=self.name)


# ── YARA Engine ────────────────────────────────────────────────────

class YaraEngine:
    """YARA rule-based scanning engine."""

    def __init__(self):
        self.name = "YaraEngine"
        self.available = HAS_YARA
        self.rules = None

        if self.available:
            self._load_rules()

    def _load_rules(self):
        """Load YARA rules from the rules directory."""
        try:
            rules_sources = {}
            loaded_count = 0
            if os.path.exists(RULES_DIR):
                for fname in os.listdir(RULES_DIR):
                    if fname.endswith((".yar", ".yara", ".enc")):
                        rule_path = os.path.join(RULES_DIR, fname)
                        try:
                            with open(rule_path, "rb") as f:
                                raw_data = f.read()
                            
                            # Decrypt if using encrypted format
                            if fname.endswith(".enc"):
                                decrypted = bytes(b ^ 0x5A for b in raw_data)
                                rules_sources[fname] = decrypted.decode("utf-8", errors="ignore")
                            else:
                                rules_sources[fname] = raw_data.decode("utf-8", errors="ignore")
                            loaded_count += 1
                        except Exception as file_err:
                            logger.error("Error reading rule file %s: %s", fname, file_err)

            if rules_sources:
                self.rules = yara.compile(sources=rules_sources)
                logger.info("Loaded %d YARA rule definitions in-memory", loaded_count)
            else:
                logger.warning("No YARA rule definitions (.yar, .yara, .enc) found in %s", RULES_DIR)
        except Exception as e:
            logger.error("Failed to compile YARA rules: %s", e)
            self.rules = None

    def reload_rules(self):
        """Reload YARA rules from disk."""
        if self.available:
            self._load_rules()

    def scan(self, file_path):
        """Scan a file against YARA rules."""
        if not self.available or not self.rules:
            return DetectionResult(engine=self.name, details="YARA not available")

        try:
            matches = self.rules.match(file_path, timeout=30)
        except Exception as e:
            logger.debug("YARA scan failed for %s: %s", file_path, e)
            return DetectionResult(engine=self.name)

        if not matches:
            return DetectionResult(engine=self.name)

        # Process matches
        threat_names = []
        max_severity = "low"
        categories = set()
        details_parts = []
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        for match in matches:
            rule_name = match.rule
            threat_names.append(rule_name)

            meta = match.meta
            sev = meta.get("severity", "medium")
            cat = meta.get("category", "unknown")
            desc = meta.get("description", rule_name)

            categories.add(cat)
            details_parts.append(f"{rule_name}: {desc}")

            if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                max_severity = sev

        primary_name = f"YARA.{'.'.join(sorted(categories)[:2])}.{threat_names[0]}"

        return DetectionResult(
            detected=True,
            threat_name=primary_name,
            threat_type="yara_match",
            severity=max_severity,
            engine=self.name,
            confidence=85 + min(len(matches) * 5, 15),
            details="; ".join(details_parts)
        )


# ── VirusTotal Cloud Engine ────────────────────────────────────────

class VirusTotalEngine:
    """Cloud-based malware verification using official VirusTotal API v3."""

    def __init__(self, config):
        self.config = config
        self.name = "VirusTotalEngine"

    def scan(self, file_path, file_hash=None):
        """Scan a file hash via VirusTotal API."""
        api_key = self.config.get("virustotal_api_key", "").strip()
        if not api_key:
            return DetectionResult(engine=self.name, details="VirusTotal Cloud: Disabled (No API Key)")

        # Only scan files with scannable extensions or if hash is given
        if not file_hash:
            hashes = compute_hashes(file_path)
            if not hashes:
                return DetectionResult(engine=self.name)
            file_hash = hashes["sha256"]

        import urllib.request
        import urllib.error
        import json

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": api_key,
            "User-Agent": "AegisAV/1.0"
        }
        
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                res_data = json.loads(response.read().decode())
                attributes = res_data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + harmless + undetected
                
                # If 2 or more engines detect it as malicious, confirm threat
                if malicious >= 2:
                    return DetectionResult(
                        detected=True,
                        threat_name=f"Cloud.VirusTotal.Malicious ({malicious}/{total} engines)",
                        threat_type="cloud_detection",
                        severity="high" if malicious < 10 else "critical",
                        engine=self.name,
                        confidence=95,
                        details=f"VirusTotal Cloud match: {malicious} engine detections."
                    )
                else:
                    return DetectionResult(
                        detected=False,
                        engine=self.name,
                        details=f"VirusTotal Cloud: clean (0/{total} flags)"
                    )
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return DetectionResult(engine=self.name, details="VirusTotal Cloud: Hash unknown (Unseen file)")
            elif e.code == 401:
                return DetectionResult(engine=self.name, details="VirusTotal Cloud: Unauthorized (Invalid Key)")
            else:
                return DetectionResult(engine=self.name, details=f"VirusTotal Cloud: API Error {e.code}")
        except Exception as e:
            return DetectionResult(engine=self.name, details="VirusTotal Cloud: Offline or timeout")


# ── Combined Scanner Engine ───────────────────────────────────────

class ScanEngine:
    """Orchestrates all detection engines for comprehensive file scanning."""

    def __init__(self, database, sensitivity="medium", config=None):
        self.db = database
        self.config = config
        self.hash_engine = HashEngine(database)
        self.heuristic_engine = HeuristicEngine(sensitivity)
        self.pe_analyzer = PEAnalyzer()
        self.yara_engine = YaraEngine()
        self.engines = [
            self.hash_engine,
            self.yara_engine,
            self.pe_analyzer,
            self.heuristic_engine,
        ]
        
        self.vt_engine = None
        if config:
            self.vt_engine = VirusTotalEngine(config)
            self.engines.append(self.vt_engine)

        logger.info("ScanEngine initialized with %d engines", len(self.engines))
        logger.info("  HashEngine: active (hashes: %d)", database.get_hash_count())
        logger.info("  YaraEngine: %s", "active" if self.yara_engine.available else "unavailable")
        logger.info("  PEAnalyzer: %s", "active" if self.pe_analyzer.available else "unavailable")
        logger.info("  HeuristicEngine: active (sensitivity: %s)", sensitivity)
        if self.vt_engine:
            has_key = bool(config.get("virustotal_api_key", "").strip())
            logger.info("  VirusTotalEngine: active (api_key: %s)", "configured" if has_key else "not_configured")

    def scan_file(self, file_path):
        """
        Scan a single file with all engines.
        Returns list of DetectionResults (only positives).
        """
        detections = []

        for engine in self.engines:
            try:
                result = engine.scan(file_path)
                if result.detected:
                    detections.append(result)
                    # If hash engine confirms known malware, we can be confident
                    if engine.name == "HashEngine" and result.confidence == 100:
                        break
            except Exception as e:
                logger.debug("Engine %s error on %s: %s", engine.name, file_path, e)

        return detections

    def get_engine_status(self):
        """Get status of all engines."""
        status = {
            "hash_engine": {
                "active": True,
                "hash_count": self.db.get_hash_count(),
            },
            "yara_engine": {
                "active": self.yara_engine.available,
                "rules_loaded": self.yara_engine.rules is not None,
            },
            "pe_analyzer": {
                "active": self.pe_analyzer.available,
            },
            "heuristic_engine": {
                "active": True,
                "sensitivity": self.heuristic_engine.sensitivity,
            },
        }
        if self.vt_engine:
            status["virustotal"] = {
                "active": bool(self.config.get("virustotal_api_key", "").strip())
            }
        return status
