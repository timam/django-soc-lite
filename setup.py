from setuptools import find_packages, setup

setup(
    name="plugin",
    install_requires=[
        "shellescape",
    ],
    packages=find_packages(exclude=["tests*"]),
)
