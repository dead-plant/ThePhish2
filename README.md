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
ThePhish2 is a fork of [ThePhish](https://github.com/emalderson/ThePhish/tree/master) made by github.com/emalderson.
Take a look at his documentation to find out more about how ThePhish works, what it is and how to use it.

Some useful resources from the original Documentation:
* [README.md](https://github.com/emalderson/ThePhish/blob/master/README.md)
    * [ThePhish example usage](https://github.com/emalderson/ThePhish/blob/master/README.md#thephish-example-usage)
    * [Implementation](https://github.com/dead-plant/ThePhish2/blob/master/README.md#implementation)
    * [Who talks about ThePhish](https://github.com/dead-plant/ThePhish2/blob/master/README.md#who-talks-about-thephish)
    * [GitHub repositories mentioning ThePhish](https://github.com/dead-plant/ThePhish2/blob/master/README.md#github-repositories-mentioning-thephish)
    * [Credits](https://github.com/dead-plant/ThePhish2/blob/master/README.md#credits)
* [Diagrams](https://github.com/emalderson/ThePhish/blob/master/diagrams.md)

github.com/emalderson also has installation/configuration guides in his [README.md](https://github.com/emalderson/ThePhish/blob/master/README.md), which i will refer to in my [Installation guide](#installation)

## How to use
Quick note: This is only a short overview of how this works. If you want a more detailed usage guide visit the [usage example](https://github.com/emalderson/ThePhish/blob/master/README.md#thephish-example-usage) of the original ThePhish repo.

1: First a user forwards an as a .eml attachment to a inbox created for ThePhish.
<img src="pictures/demo/0_do_forward.png" width="400">

2: After the user has forwarded the email the analyst can open ThePhish in his browser. There he can click "List emails" to fetch all emails from the Mailserver using IMAP.
<img src="pictures/demo/2_gui_list.png" width="700">

3:Then the analyst selects an email and clicks on "Analyze" to start the Analysis of an email.
<img src="pictures/demo/3_start_analysis_gui.png" width="700">

## What changed
### Code
* Partially refactored/reorganised to make it more maintainable
* Python 3.12
* Updated dependencies to newer versions
  * Fixed bugs
  * Fixed many security vulnerabilities

### Features
* TheHive5 (Upgraded to thehive4py:2)
  * Note: thehive4py:2 no longer supports TheHive4 or older. If you wish to use TH4 or earlier check out the original ThePhish project or switch to legacy page on this repo. (Has known bugs)
* IMAP enhanced security
  * Automatic switching between TLS and STARTTLS
  * Certificate verification
  * Option to disable certificate verification (not recommended)
* Option to disable certificate verification for TheHive and Cortex API

### Bug fixes
* Very slow analysis under certain conditions (not known)

## Setup Guide
### Installation
Coming soon...
### Configuration
Coming soon...
