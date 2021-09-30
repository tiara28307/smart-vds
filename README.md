# smart-vds
Vulnerability Detection Scanner for Smart Contracts

## Description

## Getting Started

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
3. Go to smart-vds directory: 
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
   /Users/tcarroll/codebase/CS-5374/assignment_1/PayRent.sol
    ```
   ```shell
    // Output should contain:
    {
      type: 'SourceUnit',
      children: [
        { type: 'PragmaDirective', name: 'solidity', value: '^0.8.7' },
        {
          type: 'ContractDefinition',
          name: 'PayRent',
          baseContracts: [],
          subNodes: [Array],
          kind: 'contract'
        }
      ]
    }
   ```
## Development
### Branch
1. Create your feature branch (`git checkout -b feature_name`)
    - naming convention for branches: [first_letter_of_name][last_name]_VDS-[JIRA#] e.g., tcarroll_VDS-15
2. Commit your changes (`git commit -m 'Commit message'`)
3. Push to your branch on repo (`git push`)
5. Open a Pull Request for code review and merge to master

### Testing
We utilize the JavaScript Testing Framework Jest.
- In order to run test script on your local:
    ```shell
    $ npm test
    ```

### Contact Team
TiAra Carroll - tiara.carroll@ttu.edu

Lane MacDougall - lane.macdougall@ttu.edu

Rushikesh Khamkar - rkhamkar@ttu.edu

