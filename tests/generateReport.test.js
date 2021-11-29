const assert = require('assert')

const db = require('../utils/databaseUtils')
const { generateReport } = require('../utils/generateReport')

afterAll(async () => await db.closeDbConnection())

describe('Test the generateReport function', () => {
  it('should print the generated report for vulnerabilitiesDetected array with 3 different vulnerability types (two "LOW", one "HIGH" severity)', async () => {
    try {
      // Connect to database
      await db.establishDbConnection()

      // vulnerabilitiesDetected array
      const vulnerabilitiesDetected = [
        { vid: 'UNCHECKED_CALL_RETURN_VALUE', object: [{ type: 'MemberAccess', expression: { type: 'Identifier', name: 'callee' }, memberName: 'call' }] },
        { vid: 'FLOATING_PRAGMA', object: [{ type: 'PragmaDirective', name: 'solidity', value: '^0.4.0' }] },
        { vid: 'OUTDATED_COMPILER_VERSION', object: [{ type: 'PragmaDirective', name: 'solidity', value: '^0.4.0' }] }
      ]
      await generateReport(vulnerabilitiesDetected)
    } catch (error) {
      assert.fail('Error thrown during test execution')
    }
  })

  it('should print the generated report for vulnerabilitiesDetected array with 2 different vulnerability types (one "MEDIUM", one "HIGH" severity)', async () => {
    try {
      // Connect to database
      await db.establishDbConnection()

      // vulnerabilitiesDetected array
      const vulnerabilitiesDetected = [
        {
          vid: 'AUTH_THROUGH_TX_ORIGIN',
          object: [
            { type: 'IfStatement', condition: { type: 'BinaryOperation', operator: '==', left: { type: 'MemberAccess', expression: { type: 'Identifier', name: 'msg' }, memberName: 'sender' }, right: { type: 'MemberAccess', expression: { type: 'Identifier', name: 'tx' }, memberName: 'origin' } }, trueBody: { type: 'Block', statements: [{ type: 'ExpressionStatement', expression: { type: 'BinaryOperation', operator: '+=', left: { type: 'Identifier', name: 'balance' }, right: { type: 'Identifier', name: 'amount' } } }] }, falseBody: null },
            { type: 'ExpressionStatement', expression: { type: 'FunctionCall', expression: { type: 'Identifier', name: 'require' }, arguments: [{ type: 'BinaryOperation', operator: '==', left: { type: 'MemberAccess', expression: { type: 'Identifier', name: 'tx' }, memberName: 'origin' }, right: { type: 'Identifier', name: 'owner' } }], names: [], identifiers: [] } },
            { type: 'ExpressionStatement', expression: { type: 'FunctionCall', expression: { type: 'Identifier', name: 'require' }, arguments: [{ type: 'BinaryOperation', operator: '==', left: { type: 'MemberAccess', expression: { type: 'Identifier', name: 'tx' }, memberName: 'origin' }, right: { type: 'Identifier', name: 'owner' } }], names: [], identifiers: [] } }]
        },
        { vid: 'HARDCODED_GAS_AMOUNT', object: [{ type: 'ExpressionStatement', expression: { type: 'FunctionCall', expression: { type: 'MemberAccess', expression: { type: 'Identifier', name: 'recipient' }, memberName: 'transfer' }, arguments: [{ type: 'Identifier', name: 'amount' }], names: [], identifiers: [] } }] }
      ]
      await generateReport(vulnerabilitiesDetected)
    } catch (error) {
      assert.fail('Error thrown during test execution')
    }
  })

  it('should print "No Vulnerabilities Found" for empty vulnerabilitiesDetected array', async () => {
    try {
      // Connect to database
      await db.establishDbConnection()

      // vulnerabilitiesDetected array
      const vulnerabilitiesDetected = []
      await generateReport(vulnerabilitiesDetected)
    } catch (error) {
      assert.fail('Error thrown during test execution')
    }
  })
})
