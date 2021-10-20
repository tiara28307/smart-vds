const fs = require('fs')
const assert = require('assert')
const db = require('../utils/databaseUtils')
const file = require('../utils/fileUtils')
const parser = require('@solidity-parser/parser')
const vulnerabilityDetectors = require('../utils/vulnerabilityDetectors')

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

describe('Test reentrancy (SWC-107) vulnerability detector', () => {
  it('should detect one vulnerable function call', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/ReentrancyParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const vulnerableFunctions = vulnerabilityDetectors.detectReentrancy(parseTree)
      assert.equal(vulnerableFunctions.length, 1)
    } catch (error) {
      throw error
    }
  })

  it('should detect zero vulnerable function calls', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/NoReentrancyParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const vulnerableFunctions = vulnerabilityDetectors.detectReentrancy(parseTree)
      assert.equal(vulnerableFunctions.length, 0)
    } catch (error) {
      throw error
    }
  })

  it('no function definitions; should not detect vulnerabilities', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/NoFunctionDefsParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const vulnerableFunctions = vulnerabilityDetectors.detectReentrancy(parseTree)
      assert.equal(vulnerableFunctions.length, 0)
    } catch (error) {
      throw error
    }
  })
})

describe('Test outdated compiler version (SWC-102) vulnerability detector', () => {
  it('should detect outdated compiler version', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/OutdatedCompilerParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const outdatedPragmaStatement = vulnerabilityDetectors.detectOutdatedCompilerVersion(parseTree)
      assert.deepStrictEqual(
        outdatedPragmaStatement,
        {
          type: 'PragmaDirective',
          name: 'solidity',
          value: '^0.6.0'
        })
    } catch (error) {
      throw error
    }
  })

  it('should not detect outdated compiler version', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/UpdatedCompilerParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const pragmaStatement = vulnerabilityDetectors.detectOutdatedCompilerVersion(parseTree)
      assert.deepStrictEqual(pragmaStatement, {})
    } catch (error) {
      throw error
    }
  })

  it('should return an error stating that the smart contract must have a pragma statement', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/NoPragmaStateParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const pragmaStatement = vulnerabilityDetectors.detectOutdatedCompilerVersion(parseTree)
      assert.deepStrictEqual(pragmaStatement, { error: 'Smart contract must contain exactly one pragma statement.' })
    } catch (error) {
      throw error
    }
  })
})

describe('Test floating pragma (SWC-103) vulnerability detector', () => {
  it('should detect floating pragma vulnerability', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/OutdatedCompilerParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const pragmaStatement = vulnerabilityDetectors.detectFloatingPragma(parseTree)
      assert.deepStrictEqual(pragmaStatement, {
        type: 'PragmaDirective',
        name: 'solidity',
        value: '^0.6.0'
      })
    } catch (error) {
      throw error
    }
  })

  it('should not detect floating pragma vulnerability', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/LockedPragmaParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const pragmaStatement = vulnerabilityDetectors.detectFloatingPragma(parseTree)
      assert.deepStrictEqual(pragmaStatement, {})
    } catch (error) {
      throw error
    }
  })

  it('should return an error stating that the smart contract must have a pragma statement', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/NoPragmaStateParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const pragmaStatement = vulnerabilityDetectors.detectFloatingPragma(parseTree)
      assert.deepStrictEqual(pragmaStatement, { error: 'Smart contract must contain exactly one pragma statement.' })
    } catch (error) {
      throw error
    }
  })
})

describe('Test message call with hardcoded gas amount vulnerability detector', () => {
  it('should detect transfer method call', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/TransferParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const transferMethodCall = vulnerabilityDetectors.detectTransferAndSend(parseTree)
      assert.deepStrictEqual(transferMethodCall,
        [{
          type: 'ExpressionStatement',
          expression: {
            type: 'FunctionCall',
            expression: {
              type: 'MemberAccess',
              expression: {
                type: 'MemberAccess',
                expression: {
                  type: 'Identifier',
                  name: 'msg'
                },
                memberName: 'sender'
              },
              memberName: 'transfer'
            },
            arguments: [
              {
                type: 'Identifier',
                name: 'bal'
              }
            ],
            names: [],
            identifiers: []
          }
        }])
    } catch (error) {
      throw error
    }
  })

  it('should detect send method call', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/SendMethodParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const sendMethodCall = vulnerabilityDetectors.detectTransferAndSend(parseTree)
      assert.deepStrictEqual(sendMethodCall,
        [{
          type: 'VariableDeclarationStatement',
          variables: [
            {
              type: 'VariableDeclaration',
              typeName: {
                type: 'ElementaryTypeName',
                name: 'bool',
                stateMutability: null
              },
              name: 'sent',
              identifier: {
                type: 'Identifier',
                name: 'sent'
              },
              storageLocation: null,
              isStateVar: false,
              isIndexed: false,
              expression: null
            }
          ],
          initialValue: {
            type: 'FunctionCall',
            expression: {
              type: 'MemberAccess',
              expression: {
                type: 'MemberAccess',
                expression: {
                  type: 'Identifier',
                  name: 'msg'
                },
                memberName: 'sender'
              },
              memberName: 'send'
            },
            arguments: [
              {
                type: 'Identifier',
                name: 'bal'
              }
            ],
            names: [],
            identifiers: []
          }
        }])
    } catch (error) {
      throw error
    }
  })

  it('should not detect transfer or send method call', () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/ReentrancyParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      const methodCalls = vulnerabilityDetectors.detectTransferAndSend(parseTree)
      assert.deepStrictEqual(methodCalls, [])
    } catch (error) {
      throw error
    }
  })
})

describe('Test Unchecked Call Return Value Vulnerability', () => {
  it('Unchecked Call Return Value Detected', () => {
    // Get parse tree of sample smart contract for Unchecked Call Return Value
    // Arrange
    const uncheckedCallReturnFilePath = 'tests/resources/UncheckedCallReturnValue.sol'
    const fileContents = file.readFileContents(uncheckedCallReturnFilePath).toString()
    const parseTree = parser.parse(fileContents)

    // Act
    const vulnerabilityDetected = vulnerabilityDetectors.detectUncheckedCallReturnValue(parseTree)

    // Assert
    assert.equal(vulnerabilityDetected, true, 'Should return vulnerability found.')
  })
})
