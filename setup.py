"""
ampt-generator setup
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ampt-generator',
    version='0.1.5',
    description='AMPT-generator, a simple Flask based app that generates packets to be observed by passive networking monitoring',
    long_description=long_description,
    url='https://github.com/nids-io/ampt-generator',
    author='AMPT Project',
    author_email='ampt@nids.io',
    license='BSD',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Topic :: System :: Networking :: Monitoring',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Operating System :: POSIX',
        'Framework :: Flask',
    ],
    keywords='ampt-generator, a passive network health monitoring tool',
    packages=find_packages(),
    install_requires=[
        'Flask',
        'Flask-RESTful',
        'future',
        'netifaces',
        'pyzmq',
        'scapy-python3',
    ],
    entry_points={
        'console_scripts': [
            'ampt-gen=ampt_generator.cli:ampt_gen',
            'ampt-server=ampt_generator.cli:ampt_server',
            'ampt-rulegen=ampt_generator.cli:ampt_rulegen',
        ],
    },
)
