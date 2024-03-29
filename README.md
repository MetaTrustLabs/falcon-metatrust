# Note
For developers familiar with Slither, you can directly navigate to the detectors interface to view the rules.
https://github.com/MetaTrustLabs/falcon-metatrust/tree/main/falcon/detectors
___
**We also have about 40 original rules that have not been released yet. In the future, we will gradually make the rule source code public.**
**Part of these rules，Please check "[Part of] Optimized and Added Detectors"**
# Falcon

<img src="https://metatrust.io/logo.svg" alt="Metatrust Static Analysis Framework Logo" width="500" />

> Join the Club  
> [Metatrust Telegram](https://t.me/MetatrustCTF)
> > <sub><i>- Discussions and Support </i></sub>

Welcome! We are the **Metatrust.Labs**. Over recent months, we've devoted our energies to refining and expanding the capabilities of the renowned Slither detectors. As a result, we proudly introduce **Falcon** — our advanced iteration of the Slither detectors.

Recognizing the challenges associated with code review and audit processes, we took it upon ourselves not just to enhance the sensitivity of our detectors, but also to drastically reduce the frequency of false positives. By doing so, we believe we've created the most efficient version of the Slither detectors to date. Falcon has been enriched with an abundance of new detectors, while nearly 100 of the existing ones have been optimized for better precision.

Our detectors in Falcon are designed with the primary goal of identifying potential issues to assist code auditors. They serve as a highly efficient automation tool, meticulously scanning against a vast checklist of potential vulnerabilities.

**Falcon** is a comprehensive Solidity static analysis framework crafted in Python3. Not only does it run an extensive suite of vulnerability detectors, but it also offers visual insights about contract specifics and furnishes an API designed for the easy development of custom analyses.

Building upon the foundations laid by Slither, Falcon introduces dozens of novel rules tailored for the current smart contract landscape. This includes detection mechanisms for logic inconsistencies, DeFi price manipulation vulnerabilities, centralization risks, and Time-of-Check to Time-of-Use (ToD) vulnerabilities. However, we'd like to highlight that some of these advanced checks come as premium offerings and are subject to fees.

By leveraging Falcon, developers can unearth vulnerabilities in their code, gain deeper insights into their contracts, and rapidly draft custom analyses tailored to their unique requirements.

Should you come across any issues, bugs, or vulnerabilities while utilizing our Falcon detectors, please don't hesitate to reach out. Whether it's through opening a PR/Issue or contacting us directly, we appreciate all feedback. For any further inquiries or suggestions, join our vibrant community on Discord or Telegram. We're committed to fostering a robust community, continuously enhancing our offerings, and championing collective initiatives.
- [MWE Wiki](https://metatrust.feishu.cn/wiki/wikcnAkYOYDlvHHAsnfT05TUKbc)
- [MWE Category Tree](https://metatrust.feishu.cn/wiki/wikcn1Q1wBr6zMnvoAuCMq4BLC8)
- [GPTScan](https://arxiv.org/abs/2308.03314)
    - This is our unique smart contract vulnerability scanning engine based on GPT and Falcon’s AI empower

## Install
### Pre-requisites:
Ensure you have Python (version 3.9 or newer) installed on your system.

### Installation:

1. Navigate to the Falcon project root directory.

2. Run the following command to install Falcon:
   ```bash
   pip3 install -r requirements-dev.txt
   python setup.py install
   ```

3. After successful installation, you should have access to the Falcon command-line interface.

### Structure:

#### 1. /falcon

This is similar to the `slither` folder in the Slither project. The `/falcon` folder contains the core functionalities and components of the Falcon static analysis engine, including:

- The main framework for AST analysis.
- Libraries and modules responsible for parsing smart contracts.
- Intermediate representations (IRs) for smart contracts.
- The core logic that drives the Falcon static analysis processes.

#### 2. /falcon/detectors/

This folder contains the set of detectors, primarily inspired by Slither's rules. They are designed to identify vulnerabilities, misconfigurations, and potential issues within the smart contracts:

- Each detector script in this folder targets a specific vulnerability type.
- The detectors parse and analyze the smart contract IRs to discover any potential threats.
- Detected issues will be reported with their severity, type, and a brief description to assist in understanding and mitigation.

### Basic Usage:

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
## [Part of] Optimized and Added Detectors
| **Detector Name**                       | **Detector File** | **Release Date** | **Note**                                                                                                                                                                                    | **Status**   |
|-----------------------------------------|-------------------|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Arbitrary send erc20 Basic Library      | -                 | 1 week later     | We have optimized Arbitrary send erc20 to reduce false positives                                                                                                                            | Implemented  |
| Centralized                             | -                 | relaease    | We believe that centralized risk is one of the risks that should not be ignored, so we have implemented multiple centralized risk vulnerability detection rules with different risk levels. | Implemented  |
| bad_prng                                | -                 | 1 week later     | We believe that random number vulnerabilities only occur in functions with certain specific functions, so we simply filter the functions                                                    | Implemented  |
| Transfer Inside a Loop                  | -                 | relaease     | Transfers in the loop can easily cause DOS attacks                                                                                                                                          | Implemented  |
| DeFi Related Detectors                  | -                 | relaease    | We implemented a simple price manipulation detector to detect whether there is suspicious price manipulation through taint analysis, and divided it into multiple risk levels.              | Implemented  |
| ERC                                     | -                 | 1 week later     | We have implemented detectors for multiple ERC standards                                                                                                                                    | Implemented  |
| Transaction Order Dependency            | -                 | relaease     | We implemented a detector for the Transaction Order Dependency vulnerability and divided it into multiple risk levels.                                                                      | Implemented  |
| Reentrancy Basic Library                | -                 | released         | We have optimized a variety of corner cases and significantly reduced the false alarm rate.                                                                                                 | Implemented  |
| Support on-chain data fetch             | -                 | -                | -                                                                                                                                                                                           | TODO         |
| Prompt-based AI vulnerability detection | -                 | -                | Based on our unique prompt design and vulnerability confirmation logic, we can effectively dig out some logical vulnerabilities that are difficult to discover and summarize.               | Implementing |

## Enhancements & New Detectors

Here we indicate our updates, workflows and mark completed tasks and improvements! 

> You can add your own *detector/idea/enhancement* by [opening the Issue at the following link](https://github.com/MetaTrustLabs/falcon-metatrust/issues).

Prior to adding a custom *detector*, ensure that:

1. In a documentation file, your detector is comprehensively described;
2. The detector test contract is presented and correctly compiles;
3. The detector code is presented and works properly.

Prior to adding an *idea*, ensure that:
1. Your concept or idea is well articulated;
2. A vulnerability example (or PoC) is provided;

Prior to adding an *enhancement*, ensure that:
1. Your enhancement does **not** make the base code worse;
2. Your enhancement is commented.



## Acknowledgements

Our team would like to express our deepest gratitude to the [Slither tool](https://github.com/crytic/slither#how-to-install) creators: [Josselin Feist, Gustavo Grieco, and Alex Groce](https://arxiv.org/pdf/1908.09878.pdf), as well as [Crytic](https://github.com/crytic), [Trail of Bits'](https://blog.trailofbits.com) blockchain security division, and all the people who believe in the original tool and its evolution!

**Articles:**

- [Slither](https://github.com/crytic/slither#how-to-install)
- [How do we use Slither at Pessimistic.io](https://blog.pessimistic.io/slither-an-auditors-cornucopia-a8793ea96e67)
- [Slither Explained](https://telegra.ph/Slither-Explained-04-19)
- [Slither: In-Depth](https://medium.com/coinmonks/slither-smart-contract-security-tools-29918df0fa8c)
- [Slither Review](https://blog.trailofbits.com/2019/05/27/slither-the-leading-static-analyzer-for-smart-contracts/)
- [Slither - Python](https://pypi.org/project/slither-analyzer/)
- [Reentrancy Attacks on Smart Contracts Distilled](https://blog.pessimistic.io/reentrancy-attacks-on-smart-contracts-distilled-7fed3b04f4b6)
- Be sure to [check out our blog](https://blog.pessimistic.io/) as well!

**Research Papers:**

- [GPTScan](https://arxiv.org/abs/2308.03314)This is our unique smart contract vulnerability scanning engine based on GPT and Falcon’s AIempower
- [Slither: A Static Analysis Framework For Smart Contracts](https://arxiv.org/pdf/1908.09878.pdf)
- [Detecting Vulnerable Ethereum Smart Contracts via Abstracted Vulnerability Signatures](https://arxiv.org/pdf/1912.04466.pdf)
- [Evaluating Smart Contract Static Analysis Tools Using Bug Injection](https://arxiv.org/pdf/2005.11613.pdf)
- [A Framework and DataSet for Bugs in Ethereum Smart Contracts](https://arxiv.org/pdf/2009.02066.pdf)
- [A Comprehensive Survey of Upgradeable Smart Contract Patterns](https://arxiv.org/pdf/2304.03405.pdf)

**Slither: In-Depth**

- [Accessing Private Data in Smart contracts](https://quillaudits.medium.com/accessing-private-data-in-smart-contracts-quillaudits-fe847581ce6d)
- [Simplest way to run Slither for your Smart Contract project](https://coinsbench.com/simplest-way-to-run-slither-for-your-smart-contract-project-4bdb367c06e2)
- [Slither Notes](https://hackmd.io/@DRViPNz-TVC6wqdRF8LP6w/HJHcycB9t)
- [Dataset Card for Slither Audited Smart Contracts](https://huggingface.co/datasets/mwritescode/slither-audited-smart-contracts)
- [Auditing Tools Report: Slither](https://hackmd.io/@Ydcnh_SKTIqqOYzr7HhBvQ/B1X7o1dij)
- [Bridge Security Checklist: Client Side](https://hackmd.io/@cbym/HJWQglwNs)
- [Slither & Echidna + Remappings](https://www.justinsilver.com/technology/programming/slither-echidna-remappings/)
- [Static Analysis of Smart Contracts with Slither & GitHub Actions](https://medium.com/coinmonks/static-analysis-of-smart-contracts-with-slither-github-actions-1e67e54ed8a7)

**Slitherin in mass media**

- [Week in Ethereum News](https://weekinethereumnews.com/#:~:text=Slitherin%3A%20custom%20Slither%20detectors%20with%20higher%20sensitivity%20but%20higher%20false%20positives)
- [Blockthreat](https://newsletter.blockthreat.io/p/blockthreat-week-16-2023#:~:text=Slitherin%20a%20collection%20of%20Slither%20detection%20by%20Pessimistic.io%20team)
- [Release article by officercia.eth](https://officercia.mirror.xyz/ucWYWnhBXmkKq54BIdJcH5GnrAB-nQkUsZ2F-ytEsR4)
- [Defillama](https://t.me/defillama_tg/842)

