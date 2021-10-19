const assert = require('assert')
const db = require('./utils/databaseUtils')
const file = require('./utils/fileUtils')
const parser = require('@solidity-parser/parser')
const vulnerability = require('./utils/vulnerabilityDetectors')

afterAll(async () => await db.closeDbConnection())

// Test MongoDB Cloud Database
describe('Test Cloud Database', () => {
  it('DB Connection', async () => {
    // Arrange
    let isConnected

    // Act
    try {
      isConnected = await db.establishDbConnection()
    } catch (err) {
      assert(err.message).toEqual('DB connection error')
    }

    // Assert
    assert.equal(isConnected, true)
  })
})

describe('Test Unchecked Call Return Value Vulnerability', () => {
  it('Unchecked Call Return Value Detected', () => {
    // Get parse tree of sample smart contract for Unchecked Call Return Value
    // Arrange
    const uncheckedCallReturnFilePath = './resources/UNCHECKED_CALL_RETURN_VALUE.sol'
    const fileContents = file.readFileContents(uncheckedCallReturnFilePath).toString()
    const parseTree = parser.parse(fileContents)

    // Act
    const vulnerabilityDetected = vulnerability.detectUncheckedCallReturnValue(parseTree)

    // Assert
    assert.equal(vulnerabilityDetected, true, 'Should return vulnerability found.')
  })
})
