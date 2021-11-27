const db = require('../utils/databaseUtils')
const assert = require('assert')
const file = require('../utils/fileUtils')
const parser = require('@solidity-parser/parser')
const fs = require('fs')
const { vulnerabilityScanner } = require('../vulnerability-scanner')
const { downloadReport } = require('../utils/downloadReport')
const { generateReport } = require('../utils/generateReport')

afterAll(async () => await db.closeDbConnection())

describe('Test download smart-vds report function', () => {
  it('should download smart-vds report', async () => {
    // Arrange
    const solidityFile = 'tests/resources/vulnerabilityScanner/VulnerabilityScanner5.sol'
    const fileContents = file.readFileContents(solidityFile).toString()
    const parseTree = parser.parse(fileContents)
    const testFilePath = './resources/test-report.pdf'
    const userResponse = 'yes'

    // Act
    try {
      await db.establishDbConnection()
      const vulnerabilitiesDetected = await vulnerabilityScanner(parseTree)
      await generateReport(vulnerabilitiesDetected)

      if (userResponse === 'yes') {
        await downloadReport(testFilePath)
      }

      // Assert
      assert.equal(fs.existsSync(testFilePath), true)
    } catch (err) {
      console.error(err)
    }
  })

  it('should not download smart-vds report', async () => {
    // Arrange
    const solidityFile = 'tests/resources/vulnerabilityScanner/VulnerabilityScanner5.sol'
    const fileContents = file.readFileContents(solidityFile).toString()
    const parseTree = parser.parse(fileContents)
    const testFilePath = './resources/test-report.pdf'
    const userResponse = 'no'

    // Act
    try {
      await db.establishDbConnection()
      const vulnerabilitiesDetected = await vulnerabilityScanner(parseTree)
      await generateReport(vulnerabilitiesDetected)

      if (userResponse === 'yes') {
        await downloadReport(testFilePath)
      }

      // Assert
      assert.equal(fs.existsSync(testFilePath), false)
    } catch (err) {
      console.error(err)
    }
  })
})
