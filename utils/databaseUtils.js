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
  }
}
