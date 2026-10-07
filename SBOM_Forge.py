#!/usr/bin/env python3
"""SBOM_Forge — turn dependency manifests into CycloneDX 1.4 software bills of materials.

Point SBOM_Forge at a `requirements.txt`, `Pipfile`, `Pipfile.lock`,
`poetry.lock`, or `package-lock.json` and it emits a CycloneDX 1.4 JSON BOM with
one component per dependency, each carrying a package URL (purl). The `summary`
subcommand gives a quick inventory: component count, the license set, and the
top-level vs transitive split.

Zero dependencies — Python standard library only.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import uuid


class SBOMError(Exception):
    """Raised for any unsupported, missing, or unparseable input."""


# --- helpers -----------------------------------------------------------------

def _pypi_name(name):
    """Normalize a PyPI name per PEP 503 (lowercase, runs of [-_.] -> '-')."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _pypi_purl(name, version):
    """Build a pkg:pypi purl, appending the version when known."""
    norm = _pypi_name(name)
    return f"pkg:pypi/{norm}@{version}" if version else f"pkg:pypi/{norm}"


def _npm_purl(name, version):
    """Build a pkg:npm purl, percent-encoding the @ of scoped packages."""
    enc = name.strip().replace("@", "%40")
    return f"pkg:npm/{enc}@{version}" if version else f"pkg:npm/{enc}"


def _component(name, version, ecosystem, scope, license_=None):
    """Build a normalised component dict shared by every parser."""
    if ecosystem == "npm":
        purl = _npm_purl(name, version)
    else:
        purl = _pypi_purl(name, version)
    return {
        "name": name,
        "version": version,
        "purl": purl,
        "scope": scope,          # 'top-level', 'dev', or 'transitive'
        "license": license_,     # a license name/id, or None when unknown
    }


def _split_name_version(spec):
    """Split a requirement spec like 'pkg>=1.2' into (name, version_or_None)."""
    for op in ("===", "==", "~=", ">=", "<=", "!=", ">", "<"):
        if op in spec:
            name, _, ver = spec.partition(op)
            return name.strip(), ver.strip()
    return spec.strip(), None


# --- parsers -----------------------------------------------------------------

def parse_requirements(text):
    """Parse a requirements.txt into top-level components."""
    comps = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()               # drop inline comments
        if not line or line.startswith("-"):              # skip flags/-r/-e/etc.
            continue
        spec = line.split(";", 1)[0].strip()              # drop env markers
        name, version = _split_name_version(spec)
        name = name.split("[", 1)[0].strip()              # drop extras
        if not name or name.startswith("http"):
            continue
        comps.append(_component(name, version, "pypi", "top-level"))
    return comps


def _mini_toml_sections(text, wanted):
    """Fallback TOML reader: collect simple `key = value` pairs per section."""
    out = {s: {} for s in wanted}
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line.strip("[]").strip()
            continue
        if cur in out and "=" in line:
            key, _, val = line.partition("=")
            key = key.strip().strip('"').strip("'")
            val = val.strip().strip('"').strip("'")
            out[cur][key] = val
    return out


def _try_toml(text):
    """Load TOML via tomllib when available, else return None (fallback)."""
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:
        return None
    try:
        return tomllib.loads(text)
    except Exception:
        return None


def _pipfile_version(spec):
    """Extract a bare version from a Pipfile entry (string or {version=...})."""
    if isinstance(spec, dict):
        spec = spec.get("version", "")
    if not isinstance(spec, str):
        return None
    return spec.lstrip("=~<>!").strip() or None


def parse_pipfile(text):
    """Parse a Pipfile into top-level and dev components."""
    data = _try_toml(text)
    if data is None:
        data = _mini_toml_sections(text, ["packages", "dev-packages"])
    comps = []
    for section, scope in (("packages", "top-level"), ("dev-packages", "dev")):
        for name, spec in (data.get(section) or {}).items():
            comps.append(_component(name, _pipfile_version(spec), "pypi", scope))
    if not comps:
        raise SBOMError("no [packages] or [dev-packages] found in Pipfile")
    return comps


def parse_pipfile_lock(text):
    """Parse a Pipfile.lock (JSON) into top-level and dev components."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SBOMError(f"invalid Pipfile.lock JSON: {exc}")
    comps = []
    for section, scope in (("default", "top-level"), ("develop", "dev")):
        for name, spec in (data.get(section) or {}).items():
            comps.append(_component(name, _pipfile_version(spec), "pypi", scope))
    return comps


def parse_poetry_lock(text):
    """Parse a poetry.lock (TOML) into components, all marked transitive."""
    comps = []
    data = _try_toml(text)
    packages = None
    if data is not None:
        packages = data.get("package")
    if packages is None:
        # Minimal fallback: read [[package]] blocks line by line.
        packages = []
        cur = None
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("[[package]]"):
                cur = {}
                packages.append(cur)
                continue
            if line.startswith("["):                      # any other section ends it
                cur = None
                continue
            if cur is not None and "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                if key in ("name", "version"):
                    cur[key] = val.strip().strip('"').strip("'")
    for pkg in packages:
        name = pkg.get("name")
        if not name:
            continue
        comps.append(_component(name, pkg.get("version"), "pypi", "transitive"))
    if not comps:
        raise SBOMError("no [[package]] entries found in poetry.lock")
    return comps


def _npm_name_from_path(path):
    """Recover the package name from a node_modules path."""
    idx = path.rfind("node_modules/")
    return path[idx + len("node_modules/"):] if idx != -1 else path


def _npm_license(value):
    """Normalise an npm 'license' field (string or object) to a name."""
    if isinstance(value, dict):
        return value.get("type") or value.get("name")
    return value if isinstance(value, str) else None


def parse_package_lock(text):
    """Parse a package-lock.json (lockfileVersion 1, 2 or 3)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SBOMError(f"invalid package-lock.json: {exc}")
    comps = []
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        # lockfileVersion 2/3: flat "packages" map keyed by install path.
        for path, meta in packages.items():
            if not path:                                   # the "" root entry
                continue
            name = meta.get("name") or _npm_name_from_path(path)
            version = meta.get("version")
            if not name or not version:
                continue
            depth = path.count("node_modules/")
            scope = "top-level" if depth == 1 else "transitive"
            comps.append(_component(name, version, "npm", scope,
                                    _npm_license(meta.get("license"))))
    elif isinstance(data.get("dependencies"), dict):
        # lockfileVersion 1: nested "dependencies" tree.
        def walk(deps, top):
            for name, meta in deps.items():
                if meta.get("version"):
                    comps.append(_component(
                        name, meta["version"], "npm",
                        "top-level" if top else "transitive",
                        _npm_license(meta.get("license"))))
                if isinstance(meta.get("dependencies"), dict):
                    walk(meta["dependencies"], False)
        walk(data["dependencies"], True)
    else:
        raise SBOMError("no 'packages' or 'dependencies' found in JSON")
    return comps


# --- loading / dispatch ------------------------------------------------------

def _load(path):
    """Read `path`, detect its ecosystem, and return (components, format_name)."""
    if not os.path.isfile(path):
        raise SBOMError(f"file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        raise SBOMError(f"cannot read {path}: {exc}")

    base = os.path.basename(path).lower()
    if base == "pipfile":
        return parse_pipfile(text), "pipfile"
    if base.endswith(".json"):
        # Pipfile.lock is JSON too; only accept structural lockfiles here.
        if '"lockfileVersion"' in text or '"packages"' in text or '"dependencies"' in text:
            return parse_package_lock(text), "package-lock.json"
        raise SBOMError("JSON file is not a recognizable package-lock.json")
    if base.endswith(".lock"):
        if text.lstrip().startswith("{"):
            return parse_pipfile_lock(text), "pipfile.lock"
        return parse_poetry_lock(text), "poetry.lock"
    if base.endswith(".txt"):
        return parse_requirements(text), "requirements.txt"
    raise SBOMError(f"unsupported file type: {os.path.basename(path)}")


def build_bom(components, source_path):
    """Assemble a CycloneDX 1.4 BOM dict from parsed components."""
    out = []
    for c in components:
        scope = "optional" if c["scope"] == "transitive" else "required"
        comp = {"type": "library", "name": c["name"], "scope": scope, "purl": c["purl"]}
        if c.get("version"):
            comp["version"] = c["version"]
        if c.get("license"):
            comp["licenses"] = [{"license": {"name": c["license"]}}]
        # Carry the richer top-level/transitive/dev label as a property.
        comp["properties"] = [{"name": "sbomforge:dependency", "value": c["scope"]}]
        out.append(comp)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tools": [{"vendor": "Hermtica", "name": "SBOM_Forge", "version": "1.0.0"}],
            "component": {
                "type": "application",
                "name": os.path.basename(source_path),
                "version": "0.0.0",
            },
        },
        "components": out,
    }


def _counts(components):
    """Return top-level / transitive / dev / total counts for a component list."""
    top = sum(1 for c in components if c["scope"] != "transitive")
    trans = sum(1 for c in components if c["scope"] == "transitive")
    dev = sum(1 for c in components if c["scope"] == "dev")
    return {"component_count": len(components), "top_level": top,
            "transitive": trans, "dev": dev}


# --- subcommands -------------------------------------------------------------

def cmd_generate(args):
    """Generate a CycloneDX 1.4 BOM from a manifest (`generate` subcommand)."""
    try:
        components, fmt = _load(args.file)
    except SBOMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    bom = build_bom(components, args.file)
    if args.format == "json":
        print(json.dumps(bom, indent=2))
    else:
        print(f"SBOM_Forge — CycloneDX 1.4 BOM for {args.file}")
        print(f"source format: {fmt}")
        print(f"components:    {len(bom['components'])}")
        print(f"serialNumber:  {bom['serialNumber']}")
        print()
        for comp in bom["components"]:
            ver = comp.get("version", "-")
            print(f"- {comp['name']} {ver}  {comp['purl']}")
    return 0


def cmd_summary(args):
    """Summarise a manifest's components and licenses (`summary` subcommand)."""
    try:
        components, fmt = _load(args.file)
    except SBOMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    counts = _counts(components)
    licenses = sorted({c["license"] for c in components if c.get("license")})
    result = {
        "source": args.file,
        "format": fmt,
        "component_count": counts["component_count"],
        "licenses": licenses,
        "top_level": counts["top_level"],
        "transitive": counts["transitive"],
        "dev": counts["dev"],
    }
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"SBOM_Forge — summary for {args.file}")
        print(f"format:       {fmt}")
        print(f"components:   {result['component_count']}")
        print(f"top-level:    {result['top_level']}")
        print(f"transitive:   {result['transitive']}")
        print(f"dev:          {result['dev']}")
        print("licenses:     " + (", ".join(licenses) if licenses else "(none declared)"))
    return 0


def main(argv=None):
    """Parse arguments once and dispatch to the selected subcommand."""
    # Shared --format flag, attached to EVERY subparser via parents=[common].
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )

    parser = argparse.ArgumentParser(
        prog="SBOM_Forge",
        description="Generate CycloneDX 1.4 SBOMs from dependency manifests.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("generate", parents=[common],
                           help="Generate a CycloneDX 1.4 BOM from a manifest")
    p_gen.add_argument("file", help="requirements.txt, Pipfile, Pipfile.lock, poetry.lock, or package-lock.json")
    p_gen.set_defaults(func=cmd_generate)

    p_sum = sub.add_parser("summary", parents=[common],
                           help="Summarise components and licenses from a manifest")
    p_sum.add_argument("file", help="manifest file to summarise")
    p_sum.set_defaults(func=cmd_summary)

    args = parser.parse_args(argv)  # parsed exactly once
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
