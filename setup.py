import os
from setuptools import setup, find_packages

readme_path = "README.md"
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="ln-church-agent",
    version="1.14.1", 
    packages=find_packages(include=['ln_church_agent', 'ln_church_agent.*']),
    install_requires=[
        "requests>=2.31.0",
        "pydantic>=2.0.0",
        "eth-account>=0.11.0",
        "httpx>=0.25.0"
    ],
    extras_require={
        "langchain": ["langchain-core>=0.1.0"],
        "mcp": ["mcp>=1.0.0"],
        "solana": [
            "solana>=0.34.0",
            "solders>=0.21.0"
        ],
        "svm": [
            "x402[svm]>=1.0.0",
            "solana>=0.34.0",
            "solders>=0.21.0"
        ],
        "all": [
            "langchain-core>=0.1.0", 
            "mcp>=1.0.0", 
            "solana>=0.34.0", 
            "solders>=0.21.0",
            "x402[svm]>=1.0.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "ln-church-agent=ln_church_agent.cli:main",
            "lnc-agent=ln_church_agent.cli:main",
            "ln-church-agent-mcp=ln_church_agent.integrations.mcp_inspect:main",
        ]
    },
    author="LN Church",
    description="A buyer-side HTTP 402 runtime and agent-commerce surface inspector for x402, L402, MPP, and open-web paid actions.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://kari.mayim-mayim.com/",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)