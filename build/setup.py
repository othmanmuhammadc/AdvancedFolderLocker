from setuptools import setup, find_packages

setup(
    name="advanced-folder-locker",
    version="2.0.0",
    author="Your Name",
    description="Advanced folder encryption tool with military-grade security",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "folder-locker=main:main",
        ],
    },
)




