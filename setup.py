from __future__ import absolute_import, division, print_function

from setuptools import find_packages, setup

setup(
    name="plugin",
    version="0.0.2",
    description="A Powerfull Django plugin to detect and protect All Web-based Attack.",
    install_requires=[
        "shellescape",
        "click",
        "requests",
        "bleach",
        "safety",
    ],
    long_description=open('README.md').read(),
    maintainer='threatequation',
    url = "",
    author = "",
    author_email = "",
    packages=find_packages(),
    package_data={'plugin': ['rules.json','library.txt']},
    include_package_data=True,
    test_suite="plugin.runtests.runtests",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Framework :: Django",
    ],
    entry_points="""
        [console_scripts]
        configure_plugin=plugin.configure:cli
        """
)
