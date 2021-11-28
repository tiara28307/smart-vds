# smart-vds
Vulnerability Detection Scanner for Smart Contracts

## Description
**Smart VDS** is an automated static analysis tool for detecting seven of the most common code-level vulnerabilities that 
occur in smart contracts. Smart VDS is able to run on your local machine and scan compilable Solidity files from your
machine's local storage. Smart VDS retrieves and reads the file contents of a specified Solidity file and then generates
a parse tree from the smart contract’s source code using an implementation of ANTLR 
(Another Tool for Language Recognition) specific to Solidity. After the vulnerability detection scan is complete, 
Smart VDS generates and returns a report which provides details concerning the vulnerabilities found and possible 
mitigating actions that can be taken.

#### Vunerabilities Detected:
1. Unchecked Call Return Value
2. Reentrancy
3. Authorization through tx.origin
4. Integer Overflow and Underflow
5. Outdated Compiler Version
6. Floating Pragma
7. Message Call with Hardcoded Gas Amount

## Getting Started from Blackboard (Round Three)
*Installation and usage of Smart VDS tool for Professor and TA of CS 5374.*

### Installation
1. Have [node](https://nodejs.org/en/download/) and npm installed on your local machine
2. Pull down smart-vds source code from Blackboard
3. Open your terminal or command prompt
4. Navigate to smart-vds directory
   ```shell
   $ cd smart-vds
   ```
5. Install package for smart-vds globally
   ```shell
   $ npm install -g
   ```

### Usage
1. Run command
    ```shell
    $ smart-vds
    ```
2. Input file path into Smart VDS CLI
   - File path to contract that detects hardcoded gas amount and re-entrancy: 
   
   `../smart-vds/contracts/Crowdsale.sol`
   - File path to contract that detects all 7 vulnerabilities: 
   
   `../smart-vds/tests/resources/vulnerabilityScanner/ VulnerabilityScannerAll.sol`
    ```shell
    ? Enter the file path of the Solidity smart contract that you would like to scan: 
   /Users/tcarroll/codebase/CS-5374/smart-vds/contracts/Crowdsale.sol
    ```
   Output should look like the following:
   ![alt text](https://user-images.githubusercontent.com/36643475/143727480-540e0bc0-82ba-46eb-a3a7-27902a2590fb.png)
   ![alt_text](https://user-images.githubusercontent.com/36643475/143727523-d328d378-e8c3-4977-8902-a18e4fa0ff44.png)
   ![alt_text](https://user-images.githubusercontent.com/36643475/143727536-e623ec68-2f8a-4e7e-9c72-6ba31ff8db0e.png)
3. At the end it will ask if you would like download a pdf version of the report
   - You can reply `yes` or `no`
   - If yes, the program will state if successfully downloaded and where the file is located
   
   ![alt_text](https://user-images.githubusercontent.com/36643475/143727609-465391f2-bb33-4ba4-afb8-eeee42769fc5.png)

      
## Getting Started from GitHub

### Installation
This project uses [node](https://nodejs.org/en/download/) and npm. Node.js source includes npm version.
1. Install **node** and **npm** locally
2. Clone repository. `git clone <git_repository>`
    - I suggest setting up a [ssh key](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account)
    ```shell
    // SSH
    $ git clone git@github.com:username/project_name.git

    // HTTPS
    $ git clone https://github.com/username/project_name.git
    ```
3. Navigate to smart-vds directory: 
   ```shell
   $ cd smart-vds
   ```

5. Install NPM packages globally
    ```shell
    $ npm install -g
    ```
### Usage
1. Run command
    ```shell
    $ smart-vds
    ```
2. Input file path into Smart VDS CLI
    ```shell
    ? Enter the file path of the Solidity smart contract that you would like to scan: 
   /Users/tcarroll/codebase/CS-5374/smart-vds/contracts/Crowdsale.sol
   
   // Output: report
    ```
   
## Development
*Developer guide for installation and usage for Smart VDS.*
### Dev Tools
- For development tools in npm packages can run: `npm install`
### Local Branch
1. Create your feature branch (`git checkout -b feature_name`)
    - naming convention for branches: [first_letter_of_name][last_name]_VDS-[JIRA#] e.g., tcarroll_VDS-15
2. Commit your changes (`git commit -m 'Commit message'`)
3. Push to your branch on repo (`git push`)
5. Open a Pull Request for code review and merge to master

### Testing
We utilize the JavaScript Testing Framework Jest.
- In order to run test script on your local: `npm test`

### Contact Team
TiAra Carroll - tiara.carroll@ttu.edu

Lane MacDougall - lane.macdougall@ttu.edu

Rushikesh Khamkar - rkhamkar@ttu.edu

