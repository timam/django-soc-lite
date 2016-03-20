from setuptools import find_packages, setup

setup(
    name="plugin",
    install_requires=[
        "shellescape",
        "click",
        "requests",
    ],
    packages=find_packages(exclude=["tests*"]),
    entry_points="""
        [console_scripts]
        configure_plugin=plugin.configure:cli
    """
)
