# SBOM_Forge 🔩

**Turn dependency manifests into CycloneDX 1.4 software bills of materials.** Point it at a `requirements.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, or `package-lock.json` and get a standards-shaped JSON BOM with one component per dependency, each carrying a package URL (purl). Zero dependencies, pure Python stdlib.

## Why it exists

Software bills of materials are becoming table stakes for supply-chain security, but most generators drag in a pile of dependencies of their own. SBOM_Forge reads the manifests you already have and emits CycloneDX 1.4 JSON directly — no install step, no lock-in, no network. `summary` gives you the fast inventory (counts, licenses, top-level vs transitive) when you just want to know what's inside.

## One tool, many domains

| Domain | What SBOM_Forge does for you |
|---|---|
| **Security** | Produces the component + purl inventory downstream SCA and vulnerability scanners consume |
| **DevOps / CI** | Emits a BOM artifact on every build from the lockfile already in your repo |
| **Agentic AI** | Gives LLM agents a machine-readable dependency graph to reason over and cite |
| **Compliance** | Evidence of what shipped, in a standard (CycloneDX 1.4) format |
| **Dependency hygiene** | `summary` surfaces the license set and how much of your tree is transitive |

## Install

```bash
git clone git@github.com:realMNohgee/SBOM_Forge.git
cd SBOM_Forge
python3 SBOM_Forge.py --help
```

## Quick start

```bash
cat > requirements.txt <<'EOF'
requests==2.31.0
flask>=2.3.0
urllib3
six==1.16.0  # pinned
EOF

python3 SBOM_Forge.py generate requirements.txt
```

```
SBOM_Forge — CycloneDX 1.4 BOM for requirements.txt
source format: requirements.txt
components:    4
serialNumber:  urn:uuid:...

- requests 2.31.0  pkg:pypi/requests@2.31.0
- flask 2.3.0  pkg:pypi/flask@2.3.0
- urllib3 -  pkg:pypi/urllib3
- six 1.16.0  pkg:pypi/six@1.16.0
```

### JSON BOM

```bash
python3 SBOM_Forge.py generate requirements.txt --format json
```

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    { "type": "library", "name": "requests", "version": "2.31.0", "scope": "required", "purl": "pkg:pypi/requests@2.31.0" }
  ]
}
```

### Inventory at a glance

```bash
python3 SBOM_Forge.py summary package-lock.json
```

```
SBOM_Forge — summary for package-lock.json
format:       package-lock.json
components:   42
top-level:    12
transitive:   30
dev:          0
licenses:     MIT, ISC, Apache-2.0, BSD-3-Clause
```

## Supported manifests

| File | Ecosystem | Scope handling |
|---|---|---|
| `requirements.txt` | PyPI | all top-level |
| `Pipfile` | PyPI | `packages` top-level, `dev-packages` dev |
| `Pipfile.lock` | PyPI | `default` top-level, `develop` dev |
| `poetry.lock` | PyPI | all transitive (locked set) |
| `package-lock.json` | npm | lockfileVersion 1/2/3; direct vs nested |

Any other file type exits non-zero with a clear error.

## License

MIT — see [LICENSE](LICENSE).

---

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)**
