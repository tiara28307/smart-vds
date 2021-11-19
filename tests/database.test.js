const assert = require('assert')
const db = require('../utils/databaseUtils')

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
