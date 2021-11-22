const assert = require('assert')
const db = require('../utils/databaseUtils')
const { vulnerabilities } = require('../const/vulnerabilities')

afterAll(async () => await db.closeDbConnection())

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

describe('Test database utility functions', () => {
  it('should return tx.origin vulnerability information', async () => {
    // Establish DB connection
    let isConnected
    try {
      isConnected = await db.establishDbConnection()
    } catch (error) {
      assert.fail('DB connection error')
    }
    if (isConnected) {
      // Retrieve tx.origin vulnerability information from database
      const txOriginInfo = await db.retrieveVulnerabilityInfo(vulnerabilities.AUTH_THROUGH_TX_ORIGIN)
      // Verify returned data
      assert.notEqual(txOriginInfo, null)
      assert.equal(txOriginInfo.name, 'Authorization through tx.origin')
      assert.equal(txOriginInfo.severity, 'HIGH')
      assert.equal(txOriginInfo.swcCode, 'SWC-115')
      assert.equal(txOriginInfo.mitigations.length, 1)
      assert.equal(txOriginInfo.mitigations[0], 'To authenticate the sender of a transaction, use msg.sender instead of the tx.origin global variable')
    }
  })
})
