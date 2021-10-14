const assert = require('assert')
const db = require('./utils/databaseUtils')

afterAll(async () => await db.closeDbConnection())

describe('Test Cloud Database', () => {
  it('DB Connection', async () => {
    let isConnected
    try {
      isConnected = await db.establishDbConnection()
    } catch (err) {
      assert(err.message).toEqual('DB connection error')
    }
    assert.equal(isConnected, true)
  })
})
