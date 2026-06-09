#!/usr/bin/env python3
"""ForensicHunter package setup."""

from setuptools import setup, find_packages
from pathlib import Path

HERE = Path(__file__).parent
long_description = (HERE / "README.md").read_text(encoding="utf-8")

setup(
    name="forensichunter",
    version="2.0.0",
    description="Professional digital forensics platform for Windows artifacts",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Steve Servais",
    url="https://github.com/servais1983/ForensicHunter",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    install_requires=[
        "click>=8.1",
        "rich>=13.3",
        "tqdm>=4.65",
        "psutil>=5.9",
        "pefile>=2023.2",
        "lxml>=4.9",
        "jinja2>=3.1",
        "pandas>=2.0",
        "requests>=2.31",
        "aiohttp>=3.8",
        "colorama>=0.4",
        "tabulate>=0.9",
        "pyyaml>=6.0",
        "python-dotenv>=1.0",
    ],
    extras_require={
        "yara": ["yara-python>=4.3"],
        "windows": ["pywin32>=306", "wmi>=1.5", "python-registry>=1.3"],
        "memory": ["volatility3>=2.4"],
        "api": [
            "fastapi>=0.104",
            "uvicorn[standard]>=0.24",
            "pydantic>=2.5",
            "structlog>=23.2",
        ],
        "dev": [
            "pytest>=7.3",
            "pytest-cov>=4.1",
            "pytest-asyncio>=0.21",
            "black>=23.3",
            "ruff>=0.1",
        ],
    },
    entry_points={
        "console_scripts": [
            "forensichunter=forensichunter:main",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
)
