from setuptools import setup, find_packages

setup(
    name="astra-wp-recon",
    version="1.0.0",
    description="AI-Driven WordPress User Enumeration & Attack Surface Tool",
    author="Astra Security Candidate",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "pydantic>=2.0.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "python-dotenv>=1.0.0",
        "flask>=2.3.0",
        "beautifulsoup4>=4.12.0",
    ],
    entry_points={
        "console_scripts": [
            "astra-wp-recon=astra_recon.cli:cli",
        ],
    },
)
