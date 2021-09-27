# smart-vds
Vulnerability Detection Scanner for Smart Contracts

## Description

## Getting Started

### Install

This project uses [node](https://nodejs.org/en/download/) and npm. Node.js source includes npm version.
1. Install **node** and **npm** locally
2. Clone repository. `git clone <git repository>`
    - I suggest setting up a [ssh key](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account)
    ```
    // SSH
    git clone git@github.com:username/project_name.git

    // HTTPS
    git clone https://github.com/username/project_name.git
    ```
3. Install NPM packages
    ```
    npm install
    ```

### Run Node Server
1. Run
    ```
    node app.js
    ```
2. Hosted on: http://localhost:3000/

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
    ```
    npm test or npm run test
    ```

### Contact

TiAra Carroll - tiara.carroll@ttu.edu
