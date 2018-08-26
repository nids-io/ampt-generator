# Scapy, Scapy3k, kamene and recent macOS Homebrew

From the start, we have used Scapy as the packet crafting library in
Python for generation and dispatch of healthcheck probes. Early on,
issues were found in the original Scapy, and it was not compatible
with Python 3. A fork known as Scapy3k emerged, addressing the Python 3
need and fixing whatever bugs were encountered in ampt-generator.
Additionally, we discovered that the implementation did not require
superuser privileges to craft packets. All requirements met!

Since then, secdev/scapy (scapy.net) code evolved to support Python 2
and 3. The project known as Scapy3k has now been renamed to kamene.

As of at least 2017-11-06 (likely earlier), no scapy formula exists in
Homebrew. Also no kamene. This throws a wrench in initially installing the
dependency chain for Scapy/Scapy3k by using Homebrew.

As of at least 2018-08-26 (likely earlier), relevant projects on PyPI
include:

* [scapy](https://pypi.org/project/scapy/)
* [kamene](https://pypi.org/project/kamene/)

The adjusted process, then:

0. Of course Python 3 should be set up and ready to go. Under Homebrew
   this is now just called `python`. Other packaging systems may call
   it `python3` or similar.
1. Install libdnet. It appears that it builds Python bindings automatically.

        brew install libdnet

2. Scapy requires libpcap, but macOS includes this, so the Homebrew supplied
   version may not be required.

*Notes as of 2018-08-26.*
