
  <img src="https://www.softfire.eu/wp-content/uploads/SoftFIRE_Logo_Fireball-300x300.png" width="120"/>

  Copyright © 2016-2018 [SoftFIRE](https://www.softfire.eu/) and [Fraunhofer FOKUS](https://www.fokus.fraunhofer.de/go/ngni).
  Licensed under [Apache v2 License](http://www.apache.org/licenses/LICENSE-2.0).

# sdn-proxy-osdnc

API Proxy to add Multi user capabilities to OpenSDNCore API


## Technical Requirements

 * An OpenStack installation with the OpenSDNcore add-on which replaces the vSwitch with the OpenSDNcore OpenFlow Switch
 * An OpenSDNcore SDN controller installed on the Network Node of the OpensStack Cluster
 * For OpenSDNcore a license is required from Fraunhofer FOKUS
 * ofsctl python API from Fraunhofer FOKUS

## Installation and configuration

 * install `ofsctl`, `requests`, `bottle` python modules
 * place `sdn-proxy.ini` into `/etc/` and change the default values to your needs
 * run `./sdn-proxy`

## Issue tracker

Issues and bug reports should be posted to the GitHub Issue Tracker of this project.

# What is SoftFIRE?

SoftFIRE provides a set of technologies for building a federated experimental platform aimed at the construction and experimentation of services and functionalities built on top of NFV and SDN technologies.
The platform is a loose federation of already existing testbed owned and operated by distinct organizations for purposes of research and development.

SoftFIRE has three main objectives: supporting interoperability, programming and security of the federated testbed.
Supporting the programmability of the platform is then a major goal and it is the focus of the SoftFIRE’s Second Open Call.

## Licensing and distribution
Copyright © [2016-2018] SoftFIRE project

Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


