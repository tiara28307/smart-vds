const chalk = require('chalk')
const Table = require('cli-table')

const db = require('./databaseUtils')
const vulnInfo = require('./vulnerabilityInfo')

const generateReport = async (vulnerabilitiesDetected) => {
  if (vulnerabilitiesDetected.length === 0) {
    console.log(chalk.blueBright('No Vulnerabilities Found'))
  } else {
    console.log(chalk.redBright('\nVulnerabilities Detected.'))
    console.log(chalk.greenBright('Generating Report...\n'))
    let totalVulnerabilityCount = 0
    const vulnerabilities = []
    try {
      // Print title of report
      console.log(chalk.bgBlack('Smart VDS Report\n'))
      // Print date, time (UTC)
      console.log(new Date().toLocaleString('en-US'))

      // Verify database connection
      const isConnected = db.isDbConnected()
      if (isConnected) {
        for (let i = 0; i < vulnerabilitiesDetected.length; i++) {
          const vulnTypeGroup = vulnerabilitiesDetected[i]
          const vid = vulnTypeGroup.vid
          const numberVulnerabilities = vulnTypeGroup.object.length
          totalVulnerabilityCount += numberVulnerabilities

          // Retrieve vulnerability information from database
          const vulnerabilityInfo = await db.retrieveVulnerabilityInfo(vid)
          vulnerabilityInfo.count = numberVulnerabilities
          vulnerabilityInfo.instances = vulnTypeGroup.object
          vulnerabilities.push(vulnerabilityInfo)

          // Set vulnerability information for later use
          vulnInfo.setVulnInformation(vulnerabilities)
          vulnInfo.setTotalVulnCount(totalVulnerabilityCount)
        }

        db.closeDbConnection()

        console.log('Number of Vulnerabilities Found: ' + chalk.yellowBright(`${totalVulnerabilityCount}`) + '\n')

        const table = new Table({ head: [chalk.greenBright('Name'), chalk.greenBright('Severity'), chalk.greenBright('Number Found')], colWidths: [50, 50, 50] })

        vulnerabilities.forEach((vulnerability) => {
          const tableRow = []
          tableRow.push(chalk.bold(vulnerability.name))
          if (vulnerability.severity === 'LOW') {
            tableRow.push(vulnerability.severity)
          } else if (vulnerability.severity === 'MEDIUM') {
            tableRow.push(chalk.yellowBright(vulnerability.severity))
          } else if (vulnerability.severity === 'HIGH') {
            tableRow.push(chalk.redBright(vulnerability.severity))
          }
          tableRow.push(vulnerability.count)
          table.push(tableRow)
        })

        console.log(table.toString())
        console.log('\n')
        vulnerabilities.forEach((vulnerability) => {
          console.log(chalk.greenBright.underline.bold(vulnerability.name))
          let severity
          if (vulnerability.severity === 'LOW') {
            severity = vulnerability.severity
          } else if (vulnerability.severity === 'MEDIUM') {
            severity = chalk.yellowBright(vulnerability.severity)
          } else if (vulnerability.severity === 'HIGH') {
            severity = chalk.redBright(vulnerability.severity)
          }
          console.log('Severity Level: ' + severity)
          if (vulnerability.count === 1) {
            console.log('Found: ' + chalk.yellowBright(`${vulnerability.count} `) + 'Instance')
          } else {
            console.log('Found: ' + chalk.yellowBright(`${vulnerability.count} `) + 'Instances')
          }
          let instanceCount = 0
          vulnerability.instances.forEach((instance) => {
            instanceCount += 1
            console.log(chalk.cyan(`Instance Number ${instanceCount}:`))
            console.log(chalk.cyan(`${JSON.stringify(instance)}\n`))
          })
          console.log(chalk.magentaBright.bold('Suggested Mitigations:'))
          let mitigationCount = 0
          vulnerability.mitigations.forEach((mitigation) => {
            mitigationCount += 1
            console.log(chalk.magentaBright(`${mitigationCount}: ${mitigation}`))
          })
          console.log('\n')
        })
      }
    } catch (error) {
      console.log(chalk.red(`Error encountered while generating report: ${error.message}`))
    }
  }
}

module.exports = { generateReport }
