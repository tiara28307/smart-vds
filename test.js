const assert = require('assert')
const db = require('./utils/databaseUtils')
const { JSONPath } = require('jsonpath-plus')
const file = require('./utils/fileUtils')
const parser = require('@solidity-parser/parser')

afterAll(async () => await db.closeDbConnection())

// Test MongoDB Cloud Database
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

/* Unchecked Call Return Value Vulnerability Detection
*     Checks for the following:
*       - Are there low-level calls: call, send, delegatecall, or callcode
*       - If they exist, are they not within one of the following:
*           - IfStatement, ReturnStatement, valid expression, FunctionCall, or VariableDeclaration
* */
describe('Test Unchecked Call Return Value Vulnerability', () => {
  it('Unchecked Call Return Value Detected', () => {
    // Get parse tree of sample smart contract for Unchecked Call Return Value
    const uncheckedCallReturnFilePath = './resources/UNCHECKED_CALL_RETURN_VALUE.sol'
    const fileContents = file.readFileContents(uncheckedCallReturnFilePath).toString()
    const parseTree = parser.parse(fileContents)

    // Vulnerability patterns for Unchecked Call Return Value
    const p1 = '$..statements[?(@.type != "IfStatement" && @.type != "ReturnStatement" && ' +
        '@.type != "VariableDeclarationStatement")]'
    const p2 = '$..expression[?(@.type != "FunctionCall" && (@.memberName == "call" || @.memberName == "send" || ' +
        '@.memberName == "delegatecall" || @.memberName == "callcode"))]'

    // JSON Queries for pattern matching
    // const q1 = jsonPath({ resultType: 'value' }, p1, parseTree)
    const q1 = JSONPath({ json: parseTree, path: p1, resultType: 'value' })
    const q2 = JSONPath({ json: q1, path: p2, resultType: 'value' })

    // Check if vulnerability is found
    const vulnerabilityFound = q2.length > 0

    assert.equal(vulnerabilityFound, true, 'Should return vulnerability found.')
  })
})
