# ampt-generator

Healthcheck packet generator for the AMPT passive network tools monitor.

AMPT is a practical framework designed to aid those who operate network IDS
sensors and similar passive security monitoring systems. A tailored approach
is needed to actively monitor the health and functionality of devices that
provide a service based on capturing and inspecting network traffic. AMPT
supports these types of systems by allowing operators to validate traffic
visibility and event logging on monitored network segments. Examples of
systems that can benefit from this type of monitoring are:

* [Suricata IDS][suricata]
* [Snort IDS][snort]
* [Bro IDS][bro]
* [Moloch][moloch]

See [AMPT][ampt] for more information on the AMPT framework and the problems
it solves.

**ampt-generator** functions as a simple packet crafting component in the AMPT
framework. It exposes a simple API service to receive requests from the AMPT
manager to dispatch healthcheck IP packets to monitored network segments. API
requests are authenticated using HMAC and a simplistic replay counter. It is
implemented in Python and uses the [Scapy][scapy] library for packet
generation. It currently supports Python 3 and is simple to deploy.

Other AMPT components include:

* [ampt-manager][ampt_manager] -  Management service for the AMPT passive
  network tools monitor
* [ampt-monitor][ampt_monitor] -  Sensor alert monitor core package for the
  AMPT passive network tools monitor

## Installation and usage

See the [Wiki](https://github.com/nids-io/ampt-generator/wiki/) for further
documentation.


[suricata]: https://suricata-ids.org/
[snort]: https://www.snort.org/
[bro]: https://www.bro.org/
[moloch]: https://github.com/aol/moloch
[ampt_manager]: https://github.com/nids-io/ampt-manager
[ampt_generator]: https://github.com/nids-io/ampt-generator
[ampt_monitor]: https://github.com/nids-io/ampt-monitor
[ampt]: https://github.com/nids-io/ampt-manager/wiki/AMPT
[scapy]: https://scapy.net/

