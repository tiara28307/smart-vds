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
  retrievePatterns: () => {
    const vulnerabilitiesMap = {}
    return VulnerabilityPattern.find({})
      .then(vulnerabilities => {
        vulnerabilities.forEach(vulnerability => {
          vulnerabilitiesMap[vulnerability.vulnerability_name] = vulnerability.pattern
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
  getPattern: (id) => {
    let pattern = ''
    return VulnerabilityPattern.find({ vulnerability_id: id })
      .then(vulnerabilities => {
        vulnerabilities.forEach(v => {
          pattern = v.pattern
        })
        return pattern
      }).catch(err => {
        return console.log(chalk.red(err))
      })
  }
}
