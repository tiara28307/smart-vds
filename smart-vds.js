#!/usr/bin/env node

const chalk = require('chalk')
const clear = require('clear')
const figlet = require('figlet')
const parser = require('@solidity-parser/parser')

const fileUtils = require('./utils/fileUtils')
const db = require('./utils/databaseUtils')
const fp = require('./const/download-file-path')
const { vulnerabilityScanner } = require('./vulnerability-scanner')
const { generateReport } = require('./utils/generateReport')
const { downloadReport } = require('./utils/downloadReport')

// Clear the console window
clear()

// Log utility header to the console
console.log(
  chalk.greenBright(figlet.textSync('Smart VDS', { font: 'cyberlarge', horizontalLayout: 'full' }))
)
console.log(chalk.greenBright('A vulnerability detection scanner for smart contracts\n\n'))

/* scan function
*       Purpose: To retrieve specified Solidity (*.sol) file and detect vulnerabilities within the file's source code
*       Tasks Executed By Function:
*           - Prompt user for file path of Solidity file to scan
*           - Retrieve specified file and read its contents
*           - Parse Solidity source code into a parse tree
*           - Retrieve vulnerability patterns
*           - Detect vulnerability patterns within source code
*           - Generate report of detected vulnerabilities
* */
const scan = async () => {
  try {
    // Prompt user for file path and validate input (must be a valid Solidity (*.sol) file)
    const promptAnswers = await fileUtils.promptForFilePath()
    const filePath = promptAnswers.filePath

    // Read contents of specified file
    const fileContents = fileUtils.readFileContents(filePath).toString()

    // Generate parse tree from retrieved file contents
    console.log(chalk.greenBright('Parsing Solidity source code...'))
    const parseTree = parser.parse(fileContents)

    // Connect to database
    const establishedConnection = await db.establishDbConnection()

    if (establishedConnection) {
      // Scan parse tree for vulnerabilities
      console.log(chalk.greenBright('Scanning parse tree for vulnerabilities...'))
      const vulnerabilitiesDetected = await vulnerabilityScanner(parseTree)

      // Generate report
      await generateReport(vulnerabilitiesDetected)

      // Prompt user to download report
      const promptDownload = await fileUtils.promptToDownloadReport()
      if (promptDownload.download === 'yes' || promptDownload.download === 'Yes') {
        // Download report
        await downloadReport(fp.downloadFilePath)
        console.log(chalk.greenBright(`Smart VDS Report was successfully downloaded! \nLocated at: ${fp.downloadFilePath}`))
      }
    }
  } catch (err) {
    if (err instanceof parser.ParserError) {
      console.error(chalk.red(err.errors))
    }
    console.log(chalk.red(err))
  }
}

scan()
