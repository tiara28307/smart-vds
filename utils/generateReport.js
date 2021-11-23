const chalk = require('chalk')
const Table = require('cli-table')

const db = require('./databaseUtils')

const generateReport = async (vulnerabilitiesDetected) => {
  if (vulnerabilitiesDetected.length === 0) {
    console.log(chalk.greenBright('No Vulnerabilities Found'))
  } else {
    let totalVulnerabilityCount = 0
    const vulnerabilities = []
    try {
      // Print date, time (UTC)
      console.log(chalk.greenBright(new Date().toUTCString()) + '\n\n')

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
        }

        db.closeDbConnection()

        console.log(chalk.greenBright(`Number of Vulnerabilities Found: ${totalVulnerabilityCount}`) + '\n')

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
        console.log('\n\n')
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
          console.log(chalk.greenBright('Severity Level: ') + severity)
          if (vulnerability.count === 1) {
            console.log(chalk.greenBright(`Found: ${vulnerability.count} Instance`))
          } else {
            console.log(chalk.greenBright(`Found: ${vulnerability.count} Instances`))
          }
          let instanceCount = 0
          vulnerability.instances.forEach((instance) => {
            instanceCount += 1
            console.log(chalk.greenBright(`Instance Number ${instanceCount}:`))
            console.log(chalk.greenBright(`${JSON.stringify(instance)}\n`))
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
