from __future__ import absolute_import, division, print_function

from setuptools import find_packages, setup

setup(
    name="django-soc-lite",
    version="0.0.5",
    description="A Powerfull Django plugin to detect and logging Basic Web-based Attack.",
    install_requires=[
        "click==6.6",
        "requests==2.11.1",
        "requests-cache==0.4.13",
        'shellescape==3.4.1'
    ],
    long_description=open('README.md').read(),
    maintainer='threatequation',
    url = "",
    author = "",
    author_email = "",
    packages=find_packages(),
    package_data={'django_soc_lite': ['rules.json',]},
    include_package_data=True,
    test_suite="django_soc_lite.runtests.runtests",
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
        "Programming Language :: Python :: 3.5+",
        "Framework :: Django",
    ],
)
