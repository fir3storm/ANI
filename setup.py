from setuptools import setup, find_packages

setup(
    name="ani-security",
    version="1.0.0",
    description="ANI - Adversarial Neural Inspector",
    author="Abhirup Guha",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "playwright>=1.40.0",
        "typer>=0.9.0",
        "rich>=13.0.0",
        "beautifulsoup4>=4.12.0",
        "pydantic>=2.0.0",
        "jinja2>=3.1.0",
        "cryptography>=41.0.0",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "ani=src.cli:app",
        ],
    },
    python_requires=">=3.9",
)
