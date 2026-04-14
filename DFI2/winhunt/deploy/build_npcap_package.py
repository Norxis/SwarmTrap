#!/usr/bin/env python3
"""Build npcap_mini.zip from the Npcap NSIS installer (v1.87).

Source: ~/ai-shared/npcap-1.87/npcap-1.87.exe
Extracts with 7z, picks the 6 required files (x64), creates deploy/npcap_mini.zip.

NOTES:
  - NPFInstall.exe is EXCLUDED — it fails on Windows Server 2025
    ("not a valid application for this OS platform"). Use netcfg.exe instead:
      netcfg.exe -l "C:\Program Files\Npcap\npcap.inf" -c s -i INSECURE_NPCAP
  - DLLs use the _x64 variants (Packet_x64.dll, wpcap_x64.dll) renamed to
    Packet.dll / wpcap.dll in the zip. The root-level DLLs are x86.
  - npcap_wfp.inf included for WFP callout driver support.

Uses 7z (p7zip-full) or a static 7zzs binary at /tmp/7z-static/7zzs.

Usage: python3 deploy/build_npcap_package.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

# Local copy of the installer — no download needed
NPCAP_EXE_PATH = os.path.expanduser("~/ai-shared/npcap-1.87/npcap-1.87.exe")

# Files we need and their zip layout
# Key = archive path in zip, Value = filename in extraction (may differ for x64)
REQUIRED_FILES = {
    # Driver files (from extraction root)
    "Npcap/npcap.sys":     "npcap.sys",
    "Npcap/npcap.inf":     "npcap.inf",
    "Npcap/npcap.cat":     "npcap.cat",
    "Npcap/npcap_wfp.inf": "npcap_wfp.inf",
    # x64 DLLs (renamed from _x64 variants → target C:\Windows\System32\Npcap\)
    "System32_Npcap/Packet.dll": "Packet_x64.dll",
    "System32_Npcap/wpcap.dll":  "wpcap_x64.dll",
}
# NOTE: NPFInstall.exe deliberately excluded — see docstring above.

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_ZIP = os.path.join(SCRIPT_DIR, "npcap_mini.zip")
STATIC_7Z = "/tmp/7z-static/7zzs"


def _find_7z() -> str:
    """Find a working 7z binary: system 7z, or static 7zzs."""
    if shutil.which("7z"):
        return "7z"
    if os.path.isfile(STATIC_7Z) and os.access(STATIC_7Z, os.X_OK):
        return STATIC_7Z
    print("ERROR: No 7z binary found.")
    print("  Option 1: sudo apt install p7zip-full")
    print(f"  Option 2: Place static 7zzs at {STATIC_7Z}")
    sys.exit(1)


def extract_nsis(exe_path: str, extract_dir: str) -> None:
    """Extract NSIS installer with 7z."""
    bin7z = _find_7z()
    print(f"  Using {bin7z}")
    print(f"  Extracting to {extract_dir} ...")
    result = subprocess.run(
        [bin7z, "x", "-y", f"-o{extract_dir}", exe_path],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  7z stderr: {result.stderr[:500]}")
        if not os.listdir(extract_dir):
            print("ERROR: 7z extraction produced no files")
            sys.exit(1)


def find_files(extract_dir: str) -> dict[str, str]:
    """Find all required files in the extraction tree.

    Returns {arc_path: full_path} for found files.
    """
    # Build lookup: lowercase filename -> list of full paths
    all_files: dict[str, list[str]] = {}
    for root, dirs, files in os.walk(extract_dir):
        for f in files:
            all_files.setdefault(f.lower(), []).append(os.path.join(root, f))

    found: dict[str, str] = {}
    for arc_path, src_name in REQUIRED_FILES.items():
        key = src_name.lower()
        if key in all_files:
            # Prefer root-level files (not in $PLUGINSDIR etc.)
            candidates = all_files[key]
            root_candidates = [p for p in candidates if "$PLUGINSDIR" not in p]
            found[arc_path] = root_candidates[0] if root_candidates else candidates[0]

    return found


def build_zip(found: dict[str, str]) -> None:
    """Create npcap_mini.zip."""
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc_name, src_path in sorted(found.items()):
            zf.write(src_path, arc_name)
            size = os.path.getsize(src_path)
            print(f"  + {arc_name} ({size:,} bytes)")

    zip_size = os.path.getsize(OUTPUT_ZIP)
    print(f"\nCreated {OUTPUT_ZIP} ({zip_size:,} bytes)")


def main() -> None:
    print("=" * 60)
    print("BUILD NPCAP MINI PACKAGE (v1.87, x64)")
    print("=" * 60)

    if not os.path.exists(NPCAP_EXE_PATH):
        print(f"ERROR: {NPCAP_EXE_PATH} not found")
        sys.exit(1)
    print(f"Source: {NPCAP_EXE_PATH} ({os.path.getsize(NPCAP_EXE_PATH):,} bytes)")

    with tempfile.TemporaryDirectory(prefix="npcap_build_") as tmpdir:
        extract_dir = os.path.join(tmpdir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        # Step 1: Extract
        print("\n[1] Extract NSIS installer")
        extract_nsis(NPCAP_EXE_PATH, extract_dir)

        # Step 2: Find required files
        print("\n[2] Locate required files")
        found = find_files(extract_dir)

        missing = set(REQUIRED_FILES) - set(found)
        if missing:
            print(f"\nWARNING: Missing files: {missing}")
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    rel = os.path.relpath(os.path.join(root, f), extract_dir)
                    print(f"  {rel}")
            print(f"\nProceeding with {len(found)}/{len(REQUIRED_FILES)} files...")

        if not found:
            print("ERROR: No required files found in extraction")
            sys.exit(1)

        # Step 3: Build zip
        print(f"\n[3] Build npcap_mini.zip ({len(found)} files)")
        build_zip(found)

    print("\nDone.")


if __name__ == "__main__":
    main()
