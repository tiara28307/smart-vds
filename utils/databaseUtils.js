const mongoose = require('mongoose')
const chalk = require('chalk')

const VulnerabilityPattern = require('../data-models/vulnerability-pattern')

require('dotenv').config()

module.exports = {
  establishDbConnection: () => {
    const uri = process.env.MONGODB_ATLAS_URI
    return mongoose.connect(uri)
      .then(() => {
        return true
      })
      .catch((err) => {
        console.log(chalk.red(err))
        return false
      })
  },
  isDbConnected: () => {
    const state = mongoose.connection.readyState
    switch (state) {
      case 0:
        console.log(chalk.red('Database disconnected.'))
        return false
      case 1:
        // console.log(chalk.greenBright('Database connected.'))
        return true
      case 2:
        console.log(chalk.greenBright('Database is connecting...'))
        return false
      case 3:
        console.log(chalk.red('Database is disconnecting...'))
        return false
    }
  },
  closeDbConnection: () => {
    return mongoose.disconnect()
      .then(() => {
        return true
      })
      .catch((err) => {
        console.log(chalk.red('Close database connection error: ', err))
        return false
      })
  },
  retrievePatterns: (id) => {
    let patterns = {}
    return VulnerabilityPattern.find({ vulnerability_id: id })
      .then(vulnerabilities => {
        vulnerabilities.forEach(vulnerability => {
          patterns = vulnerability.patterns
        })
        return patterns
      })
      .catch(err => {
        return console.log(chalk.red(err))
      })
  },
  retrieveAllPatterns: () => {
    const vulnerabilitiesMap = {}
    return VulnerabilityPattern.find({})
      .then(vulnerabilities => {
        vulnerabilities.forEach(vulnerability => {
          vulnerabilitiesMap[vulnerability.vulnerability_name] = vulnerability.patterns
        })
        return vulnerabilitiesMap
      })
      .catch(err => {
        return console.log(chalk.red(err))
      })
  },
  retrieveVulnerabilityInfo: (id) => {
    return VulnerabilityPattern.findOne({ vulnerability_id: id })
      .then((vulnerability) => {
        const vulnerabilityInfo = {
          name: vulnerability.vulnerability_name,
          severity: vulnerability.severity,
          swcCode: vulnerability.swc_code,
          mitigations: vulnerability.mitigation
        }
        return vulnerabilityInfo
      })
      .catch((error) => {
        return console.log(chalk.red(error))
      })
  }
}
