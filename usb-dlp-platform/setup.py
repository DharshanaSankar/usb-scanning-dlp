"""
setup.py
---------
Packaging script for the Secure USB Monitoring and Data Exfiltration
Prevention System (Phase 1).

This allows the project to be installed as a local editable package:
    pip install -e .

which makes the `agent`, `database`, `config`, and `dashboard` packages
importable from anywhere on the system, and registers a console entry
point `usb-dlp-agent` for launching the monitoring agent directly.
"""

from __future__ import annotations

from pathlib import Path

from setuptools import find_packages, setup

THIS_DIR = Path(__file__).resolve().parent
long_description = (THIS_DIR / "README.md").read_text(encoding="utf-8") if (THIS_DIR / "README.md").exists() else ""


def _read_requirements() -> list:
    req_file = THIS_DIR / "requirements.txt"
    if not req_file.exists():
        return []
    lines = req_file.read_text(encoding="utf-8").splitlines()
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]


setup(
    name="usb-dlp-platform",
    version="1.0.0",
    description=(
        "Secure USB Monitoring and Data Exfiltration Prevention System - "
        "Phase 1 (rule-based DLP for removable storage devices)"
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Final Year Cyber Security Project Team",
    license="Proprietary / Academic Use",
    python_requires=">=3.10",
    packages=find_packages(exclude=("tests", "tests.*")),
    include_package_data=True,
    install_requires=_read_requirements(),
    entry_points={
        "console_scripts": [
            "usb-dlp-agent=agent.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Topic :: Security",
    ],
)
