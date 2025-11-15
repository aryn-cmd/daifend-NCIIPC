"""
core/cve_mapper.py

Responsibilities:
- Find dependency manifests/locks in a repo (requirements.txt, Pipfile.lock, pyproject.lock, pom.xml,
  composer.lock, package-lock.json, yarn.lock (not fully supported), etc.)
- Extract package/version pairs for common ecosystems (python, java/maven, php/composer, node/npm)
- Load a local CVE index (compact JSON) and map package@version -> CVE entries
- Provide utility to build a compact index from OSV JSON records (if you have OSV export)
- CLI usage for local testing

Notes / Limitations:
- This is a best-effort, offline mapper. Mapping package names -> NVD CPE identifiers is non-trivial.
  The recommended source for accurate package -> CVE mapping is OSV (package-based records).
- For Maven (Java), groupId:artifactId is used as package key.
- This module purposely avoids external network calls and uses local JSON inputs.
"""

import os
import json
import xml.etree.ElementTree as ET
from typing import List, Tuple, Dict, Any, Optional

COMMON_PY_REQ_FILES = ("requirements.txt", "Pipfile.lock", "pyproject.toml", "poetry.lock", "Pipfile")
COMMON_JS_FILES = ("package-lock.json", "package.json", "yarn.lock")
COMMON_PHP_FILES = ("composer.lock", "composer.json")
COMMON_JAVA_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")

# -------------------------
# Loading compact CVE index
# -------------------------
def load_cve_index(path: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Load a compact CVE index from disk.
    The index should map keys like:
      - 'requests' -> [ { "cve":"CVE-xxx", "summary": "...", "versions": ["2.18.4", "2.19.0"] }, ... ]
      - 'django:1.11.0' -> [ ... ]  (specific version key)
      - 'org.apache.commons:commons-io' -> [ ... ] for maven style
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"CVE index not found: {path}")
    with open(path, "r", encoding="utf8") as fh:
        return json.load(fh)


# -------------------------
# OSV -> compact index builder
# -------------------------
def build_index_from_osv(osv_json_paths: List[str], out_path: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Build a compact package-index from OSV JSON files.
    Each OSV record (per file in osv_json_paths) is expected to contain:
      { "id": "OSV-...", "affected": [ { "package": {"ecosystem":"pip","name":"requests"}, "ranges": [...] , "versions": ["2.18.4","2.19.0"] }, ... ], ... }
    Output index keys:
      - "requests" -> list of cve-like dicts (id -> use OSV id or CVE if present)
      - "pip:requests" optionally (we keep simple name key)
    Returns the built index (and writes to out_path if provided).
    """
    index: Dict[str, List[Dict[str, Any]]] = {}
    for path in osv_json_paths:
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf8") as fh:
            try:
                rec = json.load(fh)
            except json.JSONDecodeError:
                # try reading lines (OSV sometimes stored one record per line)
                with open(path, "r", encoding="utf8") as fh2:
                    for ln in fh2:
                        if not ln.strip():
                            continue
                        try:
                            rec = json.loads(ln)
                        except Exception:
                            continue
                        _add_osv_record_to_index(rec, index)
                continue
        _add_osv_record_to_index(rec, index)
    if out_path:
        with open(out_path, "w", encoding="utf8") as fo:
            json.dump(index, fo, indent=2)
    return index

def _add_osv_record_to_index(rec: Dict[str, Any], index: Dict[str, List[Dict[str, Any]]]):
    """
    Insert one OSV-style record into the compact index.
    """
    osv_id = rec.get("id") or rec.get("osv_id")
    # prefer CVE id if present in 'aliases'
    aliases = rec.get("aliases", [])
    cve_id = None
    for a in aliases:
        if a.upper().startswith("CVE-"):
            cve_id = a
            break
    summary = rec.get("summary") or rec.get("details") or ""
    affected = rec.get("affected", [])
    for aff in affected:
        pkg = aff.get("package", {})
        name = pkg.get("name")
        eco = pkg.get("ecosystem")
        versions = aff.get("versions") or []
        entry = {
            "osv_id": osv_id,
            "cve": cve_id,
            "summary": summary,
            "ecosystem": eco,
            "versions": versions
        }
        if not name:
            continue
        # map under plain name and ecosystem:name key
        index.setdefault(name, []).append(entry)
        index.setdefault(f"{eco}:{name}", []).append(entry)


# -------------------------
# Parsers for manifests
# -------------------------
def parse_requirements_txt(path: str) -> List[Tuple[str, Optional[str]]]:
    """
    Parse a pip requirements.txt. Returns list of (package, version_or_None).
    Handles simple 'pkg==1.2.3' and 'pkg>=1.2' forms; ignores complex markers.
    """
    res = []
    if not os.path.exists(path):
        return res
    with open(path, "r", encoding="utf8", errors="ignore") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            # simple patterns
            if "==" in ln:
                pkg, ver = ln.split("==", 1); res.append((pkg.strip(), ver.strip()))
            elif ">=" in ln:
                pkg, ver = ln.split(">=", 1); res.append((pkg.strip(), None))
            elif "~=" in ln:
                pkg, ver = ln.split("~=", 1); res.append((pkg.strip(), None))
            elif ln.startswith("-e ") or ln.startswith("--editable "):
                # editable line (skip details)
                continue
            else:
                token = ln.split()[0]
                if "@" in token:
                    # git url, skip
                    continue
                res.append((token.split(";")[0].strip(), None))
    return res


def parse_pipfile_lock(path: str) -> List[Tuple[str, Optional[str]]]:
    """
    Pipfile.lock is JSON. Extract [default] and [develop] packages.
    """
    res = []
    if not os.path.exists(path):
        return res
    with open(path, "r", encoding="utf8") as fh:
        data = json.load(fh)
    for section in ("default", "develop"):
        part = data.get(section, {})
        for pkg, info in part.items():
            ver = info.get("version") or info.get("ref")
            if ver and ver.startswith("=="):
                ver = ver[2:]
            res.append((pkg, ver))
    return res


def parse_pyproject_toml_fallback(path: str) -> List[Tuple[str, Optional[str]]]:
    """
    If pyproject.toml is present but lock not available, we skip complex parsing.
    Keep minimal behavior: return empty (user should provide lock files).
    We perform a lightweight existence check so the 'path' parameter is used.
    """
    if not os.path.exists(path):
        return []
    # Detailed pyproject.toml parsing is not implemented here; callers should provide lock files.
    return []

def parse_package_lock(path: str) -> List[Tuple[str, Optional[str]]]:
    """
    Parse package-lock.json (npm) to extract top-level dependencies and versions.
    """
    res = []
    if not os.path.exists(path):
        return res
    with open(path, "r", encoding="utf8") as fh:
        data = json.load(fh)
    # package-lock has 'dependencies' mapping
    deps = data.get("dependencies", {})
    for pkg, info in deps.items():
        ver = info.get("version")
        res.append((pkg, ver))
    return res


def parse_composer_lock(path: str) -> List[Tuple[str, Optional[str]]]:
    """
    composer.lock is JSON with 'packages' list.
    """
    res = []
    if not os.path.exists(path):
        return res
    with open(path, "r", encoding="utf8") as fh:
        data = json.load(fh)
    for pkg in data.get("packages", []):
        name = pkg.get("name")
        ver = pkg.get("version")
        if name:
            res.append((name, ver))
    return res
def parse_pom_xml(path: str) -> List[Tuple[str, Optional[str]]]:
    """
    Parse a Maven pom.xml and extract groupId:artifactId and version for direct dependencies.
    This is a lightweight parser and won't resolve dependencyManagement or parent POMs.
    """
    res = []
    if not os.path.exists(path):
        return res
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception:
        return res
    # handle namespaces (strip them)
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"
    for dep in root.findall(".//{}dependency".format(ns)):
        gid = dep.find("{}groupId".format(ns))
        aid = dep.find("{}artifactId".format(ns))
        ver = dep.find("{}version".format(ns))
        # ensure both elements exist
        if gid is None or aid is None:
            continue
        gid_text = (gid.text or "").strip()
        aid_text = (aid.text or "").strip()
        if not gid_text or not aid_text:
            continue
        key = f"{gid_text}:{aid_text}"
        ver_text = (ver.text or "").strip() if (ver is not None and ver.text) else None
        res.append((key, ver_text))
    return res


# -------------------------
# Repo-level discovery and mapping
# -------------------------
def find_manifest_files(repo_root: str) -> List[str]:
    """
    Walk repo and collect known manifest/lock files.
    """
    files = []
    for root, _, filenames in os.walk(repo_root):
        # skip common large dirs
        if any(part in ('.git', 'node_modules', 'venv', '__pycache__') for part in root.split(os.sep)):
            continue
        for fn in filenames:
            if fn in COMMON_PY_REQ_FILES + COMMON_JS_FILES + COMMON_PHP_FILES + COMMON_JAVA_FILES:
                files.append(os.path.join(root, fn))
    return files


def extract_packages_from_repo(repo_root: str) -> List[Tuple[str, Optional[str]]]:
    """
    Find manifests and extract package/version pairs (best-effort).
    """
    pkgs: List[Tuple[str, Optional[str]]] = []
    manifests = find_manifest_files(repo_root)
    for mf in manifests:
        fn = os.path.basename(mf)
        if fn == "requirements.txt":
            pkgs.extend(parse_requirements_txt(mf))
        elif fn == "Pipfile.lock":
            pkgs.extend(parse_pipfile_lock(mf))
        elif fn in ("pyproject.toml", "Pipfile"):
            pkgs.extend(parse_pyproject_toml_fallback(mf))
        elif fn == "package-lock.json":
            pkgs.extend(parse_package_lock(mf))
        elif fn == "composer.lock":
            pkgs.extend(parse_composer_lock(mf))
        elif fn == "pom.xml":
            pkgs.extend(parse_pom_xml(mf))
        elif fn == "package.json":
            # try to get dependencies block from package.json
            with open(mf, "r", encoding="utf8") as fh:
                data = json.load(fh)
            deps = data.get("dependencies", {})
            for pkg, ver in deps.items():
                pkgs.append((pkg, ver))
        # other files ignored for now
    return pkgs


def map_packages_to_cves(packages: List[Tuple[str, Optional[str]]], cve_index: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Map a list of (pkg, ver) to CVE entries from cve_index.
    cve_index keys can be:
      - pkg (plain)
      - ecosystem:pkg (e.g., pip:requests)
      - group:artifact for Maven
    Matching strategy:
      1) exact key "pkg:version" if present
      2) package name only -> return all entries (caller can inspect versions)
      3) ecosystem-style keys are supported if present in index
    Returns list of matches: { package, version, index_key, matched_entry }
    """
    matches = []
    for pkg, ver in packages:
        if not pkg:
            continue
        # try direct exact key
        exact_key = f"{pkg}:{ver}" if ver else pkg
        if ver and exact_key in cve_index:
            for e in cve_index[exact_key]:
                matches.append({"package": pkg, "version": ver, "key": exact_key, "entry": e})
            continue
        # try plain package key
        if pkg in cve_index:
            for e in cve_index[pkg]:
                matches.append({"package": pkg, "version": ver, "key": pkg, "entry": e})
            continue
        # try lowercase fallback
        low = pkg.lower()
        if low in cve_index:
            for e in cve_index[low]:
                matches.append({"package": pkg, "version": ver, "key": low, "entry": e})
            continue
        # try ecosystem-prefixed keys (common)
        for prefix in ("pip:", "npm:", "composer:", "maven:"):
            k = f"{prefix}{pkg}"
            if k in cve_index:
                for e in cve_index[k]:
                    matches.append({"package": pkg, "version": ver, "key": k, "entry": e})
                break
    return matches


def map_repo_dependencies_to_cves(repo_root: str, cve_index: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """
    High-level function: extract packages from repo and map them to CVEs.
    Returns:
    {
      "repo": repo_root,
      "packages": [ (pkg, ver), ... ],
      "cve_matches": [ { package, version, key, entry }, ... ]
    }
    """
    pkgs = extract_packages_from_repo(repo_root)
    matches = map_packages_to_cves(pkgs, cve_index)
    return {
        "repo": repo_root,
        "packages_found": pkgs,
        "cve_matches": matches
    }


# -------------------------
# CLI for local testing
# -------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Map repository dependencies to local CVE index (offline)")
    parser.add_argument("--repo", "-r", required=True, help="Path to repository")
    parser.add_argument("--cve_index", "-c", required=False, help="Path to compact CVE index JSON (optional)")
    parser.add_argument("--build_from_osv", "-b", nargs="*", help="Optional path(s) to OSV JSON files to build index from (writes tmp_index.json)")
    args = parser.parse_args()

    index = {}
    if args.build_from_osv:
        print("[INFO] Building compact index from OSV JSON files (this may take a while)...")
        index = build_index_from_osv(args.build_from_osv, out_path=None)
        print(f"[INFO] Built index with {len(index)} keys")
    elif args.cve_index:
        index = load_cve_index(args.cve_index)
        print(f"[INFO] Loaded CVE index with {len(index)} keys")

    result = map_repo_dependencies_to_cves(args.repo, index)
    outp = os.path.join(os.getcwd(), "output", f"cve_matches_{os.path.basename(args.repo)}.json")
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    with open(outp, "w", encoding="utf8") as fo:
        json.dump(result, fo, indent=2)
    print(f"[DONE] Wrote results to {outp}")
    print(f"[SUMMARY] packages_found={len(result['packages_found'])}, cve_matches={len(result['cve_matches'])}")
