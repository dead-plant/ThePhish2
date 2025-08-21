# ThePhish2

<div>
  <p align="center">
    <img src="pictures/logo.png" width="800"> 
  </p>
</div>

ThePhish is an automated phishing email analysis tool based on [TheHive](https://github.com/TheHive-Project/TheHive), [Cortex](https://github.com/TheHive-Project/Cortex/) and [MISP](https://github.com/MISP/MISP). It is a web application written in Python 3 and based on Flask that automates the entire analysis process starting from the extraction of the observables from the header and the body of an email to the elaboration of a verdict which is final in most cases. In addition, it allows the analyst to intervene in the analysis process and obtain further details on the email being analyzed if necessary. In order to interact with TheHive and Cortex, it uses [TheHive4py](https://github.com/TheHive-Project/TheHive4py) and [Cortex4py](https://github.com/TheHive-Project/Cortex4py), which are the Python API clients that allow using the REST APIs made available by TheHive and Cortex respectively.

[![OS](https://img.shields.io/badge/OS-Linux-red?style=flat&logo=linux)](#)
[![made-with-python](https://img.shields.io/badge/Made%20with-Python%203.12-1f425f.svg?logo=python)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-not%20available-red.svg?style=flat&logo=docker)](#)
[![Maintenance](https://img.shields.io/badge/Maintained-yes-green.svg)](https://github.com/dead-plant/ThePhish2)
[![GitHub](https://img.shields.io/github/license/dead-plant/ThePhish2)](https://github.com/dead-plant/ThePhish2/blob/master/LICENSE)
[![Documentation](https://img.shields.io/badge/Documentation-in%20progress-blue.svg?style=flat)](https://github.com/dead-plant/ThePhish2)


## Table of contents
* [Overview](#overview)
* [How to use](#how-to-use)
* [What changed](#what-changed)
* [Setup guide](#setup-guide)
  * [Installation](#installation)
  * [Configuration](#configuration)
* [Contributing](https://github.com/dead-plant/ThePhish2/blob/master/CONTRIBUTING.md)
* [Code of conduct](https://github.com/dead-plant/ThePhish2/blob/master/CODE_OF_CONDUCT.md)
* [License](https://github.com/dead-plant/ThePhish2/blob/master/LICENSE)

## Overview
ThePhish2 is a fork of [ThePhish](https://github.com/emalderson/ThePhish) by [@emalderson](https://github.com/emalderson).
Take a look at the upstream documentation to find more detailed information on how ThePhish works, what it is, and how to use it.

Some useful resources from the original documentation:
* [README.md](https://github.com/emalderson/ThePhish/blob/master/README.md)
  * [ThePhish example usage](https://github.com/emalderson/ThePhish/blob/master/README.md#thephish-example-usage)
  * [Implementation](https://github.com/emalderson/ThePhish/blob/master/README.md#implementation)
  * [Who talks about ThePhish](https://github.com/emalderson/ThePhish/blob/master/README.md#who-talks-about-thephish)
  * [GitHub repositories mentioning ThePhish](https://github.com/emalderson/ThePhish/blob/master/README.md#github-repositories-mentioning-thephish)
  * [Credits](https://github.com/emalderson/ThePhish/blob/master/README.md#credits)
* [Diagrams](https://github.com/emalderson/ThePhish/blob/master/diagrams.md)

The upstream repository also provides installation and configuration guides, which I partially reference in my [Setup guide](#setup-guide).

## How to use
Quick note: this is only a short overview. For a detailed walkthrough, see the upstream [usage example](https://github.com/emalderson/ThePhish/blob/master/README.md#thephish-example-usage).

1. Forward the suspicious message as a `.eml` attachment (not inline) to the mailbox monitored by ThePhish2.
<img src="pictures/demo/0_do_forward.png" width="400">
2. In your browser, open ThePhish2 and click `List emails` to fetch messages from the mail server via IMAP.
<img src="pictures/demo/2_gui_list.png" width="700">
3. Select an email and click `Analyze` to create a TheHive case and run Cortex analyzers.
<img src="pictures/demo/3_start_analysis_gui.png" width="700">
4. Review the verdict in the UI. If configured correctly, export malicious cases to MISP.

## What changed
### Code
* Partially refactored/reorganized for better maintainability
* Make it work on Python 3.12
* Updated dependencies to current versions
  * Fixed bugs
  * Addressed multiple security vulnerabilities

### Features
* TheHive 5 support (Upgraded to thehive4py v2)
  * Breaking: thehive4py v2 does not support TheHive 4 or earlier. If you still need TheHive 4 compatibility, use the upstream project or the legacy branch of this fork, though this might have issues.
* IMAP
  * STARTTLS support
  * Automatic switching between TLS and STARTTLS
  * Certificate verification
  * Option to disable certificate verification (not recommended)
* Other
  * Added the option to disable certificate verification for TheHive API and Cortex API

### Bug fixes
* Very slow analysis under certain conditions (exact conditions unknown)

## Setup Guide
### Installation
Coming soon...
### Configuration
Coming soon...
