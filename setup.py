import os
from setuptools import setup, find_packages

readme_path = "README.md"
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="ln-church-agent",
    version="0.9.3",
    packages=['ln_church_agent', 'ln_church_agent.crypto', 'ln_church_agent.integrations'],
    install_requires=[
        "requests>=2.31.0",
        "pydantic>=2.0.0",
        "eth-account>=0.11.0",
        "httpx>=0.25.0"
    ],
    extras_require={
        "langchain": ["langchain-core>=0.1.0"],
        "mcp": ["mcp>=1.0.0"]
    },
    author="LN Church",
    description="A Python reference client for HTTP 402 settlement across x402, L402, MPP, and fallback flows.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://kari.mayim-mayim.com/",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)