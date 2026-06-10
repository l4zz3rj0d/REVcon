from setuptools import setup, find_packages

setup(
    name="revcon",
    version="1.0.0",
    author="Lazzer",
    description="Redesigned Automated reconnaissance and triage framework for reverse engineering and CTFs",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/l4zz3rj0d/REVcon",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "revcon=revcon:main",
        ],
    },
    install_requires=[
        "colorama>=0.4.6",
        "capstone>=5.0.1",
        "pyelftools>=0.29",
        "pefile>=2023.2.7",
        "macholib>=1.16.2",
        "unicorn>=2.0.1",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.11",
)
