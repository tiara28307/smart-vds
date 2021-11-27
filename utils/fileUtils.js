const fs = require('fs')
const path = require('path')
const inquirer = require('inquirer')
const chalk = require('chalk')

/* fileExists function
*       Purpose: Determine if the file located at the provided file path exists
*       Tasks Executed By Function:
*           - Run the fs package's existsSync function
* */
const fileExists = (filePath) => {
  return fs.existsSync(filePath)
}

module.exports = {
  /* promptForFilePath function
    *       Purpose: Prompt user for the file path of the Solidity file to be scanned
    *       Tasks Executed By Function:
    *           - Run the inquirer package's prompt function
    * */
  promptForFilePath: () => {
    const questions = [{
      name: 'filePath',
      type: 'input',
      message: chalk.greenBright('Enter the file path of the Solidity smart contract that you would like to scan:'),
      validate: (value) => {
        if (value.length > 0) {
          if (fileExists(value)) {
            if (path.extname(value) === '.sol') {
              return true
            } else {
              return chalk.red('Smart VDS only scans Solidity (*.sol) files. Please enter the file path of a valid Solidity file.')
            }
          } else {
            return chalk.red('Invalid file path. Please try again.')
          }
        } else {
          return chalk.red('Please enter the file path of the Solidity smart contract.')
        }
      }
    }]
    return inquirer
      .prompt(questions)
      .then(answers => {
        return answers
      })
      .catch(err => {
        if (err.isTtyError) {
          return console.log(chalk.red('Prompt could not be rendered in the current environment.'))
        } else {
          return console.log(chalk.red(err))
        }
      })
  },

  /* readFileContents function
    *       Purpose: Read in the contents of the file located at the specified file path
    *       Tasks Executed By Function:
    *           - Run the fs package's readFileSync function
    * */
  readFileContents: (filePath) => {
    // Retrieve file contents once validated
    return fs.readFileSync(filePath, { encoding: 'utf8', flag: 'r' })
  },

  /* promptToDownloadReport function
    *       Purpose: Prompt user to download Smart VDS Report
    *       Tasks Executed By Function:
    *           - Run the inquirer package's prompt function
    * */
  promptToDownloadReport: () => {
    const questions = [{
      name: 'download',
      type: 'input',
      message: chalk.greenBright('Would you like to download Smart VDS Report? (yes/no):'),
      validate: (answer) => {
        if (answer.length > 0) {
          if (answer === 'yes' || answer === 'Yes') {
            return true
          } else if (answer === 'no' || answer === 'No') {
            return true
          } else {
            return chalk.red('Invalid response. Must type "yes" or "no".')
          }
        } else {
          return chalk.red('Please enter if you would like to download report.')
        }
      }
    }]
    return inquirer
      .prompt(questions)
      .then(answers => {
        return answers
      })
      .catch(err => {
        if (err.isTtyError) {
          return console.log(chalk.red('Prompt could not be rendered in the current environment.'))
        } else {
          return console.log(chalk.red(err))
        }
      })
  }
}
