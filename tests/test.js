const fs = require('fs')
const assert = require('assert')
const db = require('../utils/databaseUtils')
const file = require('../utils/fileUtils')
const parser = require('@solidity-parser/parser')
const vulnerabilityDetectors = require('../utils/vulnerabilityDetectors')
const { vulnerabilities } = require('../const/vulnerabilities')

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
  it('should detect one vulnerable function call', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/ReentrancyParseTree.json', {
        encoding: 'utf-8',
        flag: 'r'
      })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.REENTRANCY)
      const vulnerableFunctions = vulnerabilityDetectors.detectReentrancy(parseTree, patterns)
      assert.equal(vulnerableFunctions.length, 1)
    } catch (error) {
      throw error
    }
  })

  it('should detect zero vulnerable function calls', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/NoReentrancyParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.REENTRANCY)
      const vulnerableFunctions = vulnerabilityDetectors.detectReentrancy(parseTree, patterns)
      assert.equal(vulnerableFunctions.length, 0)
    } catch (error) {
      throw error
    }
  })

  it('no function definitions; should not detect vulnerabilities', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/NoFunctionDefsParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.REENTRANCY)
      const vulnerableFunctions = vulnerabilityDetectors.detectReentrancy(parseTree, patterns)
      assert.equal(vulnerableFunctions.length, 0)
    } catch (error) {
      throw error
    }
  })
})

describe('Test outdated compiler version (SWC-102) vulnerability detector', () => {
  it('should detect outdated compiler version', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/OutdatedCompilerParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.OUTDATED_COMPILER_VERSION)
      const outdatedPragmaStatement = vulnerabilityDetectors.detectOutdatedCompilerVersion(parseTree, patterns)
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

  it('should not detect outdated compiler version', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/UpdatedCompilerParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.OUTDATED_COMPILER_VERSION)
      const pragmaStatement = vulnerabilityDetectors.detectOutdatedCompilerVersion(parseTree, patterns)
      assert.deepStrictEqual(pragmaStatement, {})
    } catch (error) {
      throw error
    }
  })

  it('should return an error stating that the smart contract must have a pragma statement', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/NoPragmaStateParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.OUTDATED_COMPILER_VERSION)
      const pragmaStatement = vulnerabilityDetectors.detectOutdatedCompilerVersion(parseTree, patterns)
      assert.deepStrictEqual(pragmaStatement, { error: 'Smart contract must contain exactly one pragma statement.' })
    } catch (error) {
      throw error
    }
  })
})

describe('Test floating pragma (SWC-103) vulnerability detector', () => {
  it('should detect floating pragma vulnerability', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/OutdatedCompilerParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.FLOATING_PRAGMA)
      const pragmaStatement = vulnerabilityDetectors.detectFloatingPragma(parseTree, patterns)
      assert.deepStrictEqual(pragmaStatement, {
        type: 'PragmaDirective',
        name: 'solidity',
        value: '^0.6.0'
      })
    } catch (error) {
      throw error
    }
  })

  it('should not detect floating pragma vulnerability', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/LockedPragmaParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.FLOATING_PRAGMA)
      const pragmaStatement = vulnerabilityDetectors.detectFloatingPragma(parseTree, patterns)
      assert.deepStrictEqual(pragmaStatement, {})
    } catch (error) {
      throw error
    }
  })

  it('should return an error stating that the smart contract must have a pragma statement', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/NoPragmaStateParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.FLOATING_PRAGMA)
      const pragmaStatement = vulnerabilityDetectors.detectFloatingPragma(parseTree, patterns)
      assert.deepStrictEqual(pragmaStatement, { error: 'Smart contract must contain exactly one pragma statement.' })
    } catch (error) {
      throw error
    }
  })
})

describe('Test message call with hardcoded gas amount vulnerability detector', () => {
  it('should detect transfer method call', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/TransferParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.HARDCODED_GAS_AMOUNT)
      const transferMethodCall = vulnerabilityDetectors.detectTransferAndSend(parseTree, patterns)
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

  it('should detect send method call', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/SendMethodParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.HARDCODED_GAS_AMOUNT)
      const sendMethodCall = vulnerabilityDetectors.detectTransferAndSend(parseTree, patterns)
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

  it('should not detect transfer or send method call', async () => {
    // eslint-disable-next-line no-useless-catch
    try {
      const parseTreeFile = fs.readFileSync('tests/resources/json/ReentrancyParseTree.json', { encoding: 'utf-8', flag: 'r' })
      const parseTree = JSON.parse(parseTreeFile.toString())
      await db.establishDbConnection()
      const patterns = await db.retrievePatterns(vulnerabilities.HARDCODED_GAS_AMOUNT)
      const methodCalls = vulnerabilityDetectors.detectTransferAndSend(parseTree, patterns)
      assert.deepStrictEqual(methodCalls, [])
    } catch (error) {
      throw error
    }
  })
})

describe('Test Unchecked Call Return Value (SWC-104) Vulnerability', () => {
  it('should detect one unchecked call return value', async () => {
    // Arrange
    const uncheckedCallReturnValueFilePath = 'tests/resources/solidity/UncheckedCallReturnValue.sol'
    const fileContents = file.readFileContents(uncheckedCallReturnValueFilePath).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.UNCHECKED_CALL_RETURN_VALUE)

    // Act
    const vulnerabilityDetected = await vulnerabilityDetectors.detectUncheckedCallReturnValue(parseTree, patterns)

    // Assert
    assert.equal(vulnerabilityDetected.length === 1, true, 'Should return vulnerability found.')
  })

  it('should detect multiple unchecked call return values', async () => {
    // Arrange
    const uncheckedCallReturnValuesFilePath = 'tests/resources/solidity/UncheckedCallReturnValues.sol'
    const fileContents = file.readFileContents(uncheckedCallReturnValuesFilePath).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.UNCHECKED_CALL_RETURN_VALUE)

    // Act
    const vulnerabilityDetected = await vulnerabilityDetectors.detectUncheckedCallReturnValue(parseTree, patterns)

    // Assert
    assert.equal(vulnerabilityDetected.length > 0, true, 'Should return multiple vulnerabilities found.')
  })

  it('should not detect unchecked call return value', async () => {
    // Arrange
    const uncheckedCallReturnValuesFilePath = 'tests/resources/solidity/NoUncheckedCallReturnValue.sol'
    const fileContents = file.readFileContents(uncheckedCallReturnValuesFilePath).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.UNCHECKED_CALL_RETURN_VALUE)

    // Act
    const vulnerabilityDetected = await vulnerabilityDetectors.detectUncheckedCallReturnValue(parseTree, patterns)

    // Assert
    assert.equal(vulnerabilityDetected.length > 0, false, 'Should return no vulnerabilities found.')
  })
})
