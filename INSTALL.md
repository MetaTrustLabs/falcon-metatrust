## INSTALL.md

# Falcon Static Analysis for Smart Contracts

Welcome to the Falcon project! Falcon is designed to provide thorough static analysis for your smart contracts. Here's how to get started with the installation and basic usage of Falcon.

## Pre-requisites:
Ensure you have Python (version 3.9 or newer) installed on your system.

## Installation:

1. Navigate to the Falcon project root directory.

2. Run the following command to install Falcon:
   ```bash
   pip3 install -r requirements-dev.txt
   python setup.py install
   ```

3. After successful installation, you should have access to the Falcon command-line interface.

## Structure:

### 1. /falcon

This is similar to the `slither` folder in the Slither project. The `/falcon` folder contains the core functionalities and components of the Falcon static analysis engine, including:

- The main framework for AST analysis.
- Libraries and modules responsible for parsing smart contracts.
- Intermediate representations (IRs) for smart contracts.
- The core logic that drives the Falcon static analysis processes.

### 2. /falcon/detectors/

This folder contains the set of detectors, primarily inspired by Slither's rules. They are designed to identify vulnerabilities, misconfigurations, and potential issues within the smart contracts:

- Each detector script in this folder targets a specific vulnerability type.
- The detectors parse and analyze the smart contract IRs to discover any potential threats.
- Detected issues will be reported with their severity, type, and a brief description to assist in understanding and mitigation.

## Basic Usage:

To scan a smart contract without installing the package:

1. Navigate to the Falcon project root directory.

2. Run the following command:
   ```bash
   pip3 install -r requirements-dev.txt
   python -m falcon [relative file based on root directory of falcon]
   ```

For example, to scan a contract located at `contracts/MyContract.sol`:
   ```bash
   pip3 install -r requirements-dev.txt
   python -m falcon contracts/MyContract.sol
   ```

## Contribution:

We're always eager to improve Falcon! If you have any suggestions, issues, or would like to contribute to the project, please refer to our contribution guidelines and reach out.

Thank you for choosing Falcon for your smart contract static analysis needs!