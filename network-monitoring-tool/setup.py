from setuptools import setup, find_packages

setup(
    name="network-monitoring-tool",
    version="1.0.0",
    description="Python-based CLI tool for automated network device discovery, health checks, and alerting",
    author="Network Engineer",
    packages=find_packages(),
    install_requires=[
        "pysnmp>=4.4.12",
        "pythonping>=1.1.4",
        "click>=8.1.0",
        "rich>=13.0.0",
        "flask>=2.3.0",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
        "schedule>=1.2.0",
        "requests>=2.31.0",
        "jinja2>=3.1.0",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "netmon=src.cli:cli",
        ],
    },
)
