from setuptools import setup, find_packages

setup(
    name="mrraj",
    version="3.0.0",
    author="Mr Raj",
    description="MrRaj Simple Scan Tool",
    packages=find_packages(),
    install_requires=["requests"],
    entry_points={
        "console_scripts": [
            "mrraj=mrraj.main:run"
        ]
    },
    python_requires=">=3.8",
)