const fs = require('fs')
const assert = require('assert')
const db = require('../utils/databaseUtils')
const file = require('../utils/fileUtils')
const parser = require('@solidity-parser/parser')
const vulnerabilityDetectors = require('../utils/vulnerabilityDetectors')
const { vulnerabilities } = require('../const/vulnerabilities')
const { vulnerabilityScanner } = require('../vulnerability-scanner')

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
        outdatedPragmaStatement[0],
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
      assert.deepStrictEqual(pragmaStatement, [])
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
      assert.deepStrictEqual(pragmaStatement[0], { error: 'Smart contract must contain exactly one pragma directive.' })
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
      assert.deepStrictEqual(pragmaStatement[0], {
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
      assert.deepStrictEqual(pragmaStatement, [])
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
      assert.deepStrictEqual(pragmaStatement[0], { error: 'Smart contract must contain exactly one pragma directive.' })
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
    const uncheckedCallReturnValueFilePath = 'tests/resources/solidity/Lotto_UncheckedCallReturnValue.sol'
    const fileContents = file.readFileContents(uncheckedCallReturnValueFilePath).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.UNCHECKED_CALL_RETURN_VALUE)

    // Act
    const vulnerabilityDetected = vulnerabilityDetectors.detectUncheckedCallReturnValue(parseTree, patterns)

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
    const vulnerabilityDetected = vulnerabilityDetectors.detectUncheckedCallReturnValue(parseTree, patterns)

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
    const vulnerabilityDetected = vulnerabilityDetectors.detectUncheckedCallReturnValue(parseTree, patterns)

    // Assert
    assert.equal(vulnerabilityDetected.length > 0, false, 'Should return no vulnerabilities found.')
  })
})

describe('Test TX Origin Vulnerability', () => {
  it('should detect tx.origin in if statement and require statement', async () => {
    const txoriginfile = 'tests/resources/Tx.origin/txorigin1.sol'
    const fileContents = file.readFileContents(txoriginfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.AUTH_THROUGH_TX_ORIGIN)
    const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree, patterns)
    assert.equal(TxOriginFound.length, 2, 'Vulnerability TX.Origin is not found in Smart Contract.')
  })

  it('should detect 3 vulnerable statements: one if statement, one require statement, and one assignment statement', async () => {
    const txoriginfile = 'tests/resources/Tx.origin/txorigin2.sol'
    const fileContents = file.readFileContents(txoriginfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.AUTH_THROUGH_TX_ORIGIN)
    const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree, patterns)
    assert.equal(TxOriginFound.length, 3, 'Vulnerability TX.Origin is found in Smart Contract')
  })

  // tx.origin is not utilized by tested smart contract
  it('should not detect any vulnerable statements', async () => {
    const txoriginfile = 'tests/resources/Tx.origin/txorigin3.sol'
    const fileContents = file.readFileContents(txoriginfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.AUTH_THROUGH_TX_ORIGIN)
    const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree, patterns)
    assert.equal(TxOriginFound.length, 0, 'Vulnerability TX.Origin is found in Smart Contract')
  })

  it('should detect a single vulnerable assignment statement', async () => {
    const txoriginfile = 'tests/resources/Tx.origin/txorigin4.sol'
    const fileContents = file.readFileContents(txoriginfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.AUTH_THROUGH_TX_ORIGIN)
    const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree, patterns)
    assert.equal(TxOriginFound.length, 1, 'Vulnerability TX.Origin is not found in Smart Contract')
  })
})

describe('Test Underflow Vulnerability', () => {
  // Underflow condition found in Smart Contract
  it('Underflow condition found in Smart Contract', async () => {
    const underflowfile = 'tests/resources/Underflow/underflow1.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is not found in Smart Contract.')
  })

  it('should not detect vulnerability because compiler version > 0.8.0', async () => {
    const underflowFile = 'tests/resources/Underflow/underflow13.sol'
    const fileContents = file.readFileContents(underflowFile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 0, 'Vulnerability Underflow was found in Smart Contract.')
  })

  // Underflow condition found in Smart Contract
  it('Underflow condition is handled in If Statement', async () => {
    const underflowfile = 'tests/resources/Underflow/underflow2.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is found in Smart Contract.')
  })

  // Underflow condition found in Smart Contract
  it('Underflow condition found in If Statement', async () => {
    const underflowfile = 'tests/resources/Underflow/underflow10.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is not found in Smart Contract.')
  })

  // Underflow condition is handled in If Statement
  it('Underflow condition is handled in If Statement with multiple condition', async () => {
    const underflowfile = 'tests/resources/Underflow/underflow11.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 0, 'Vulnerability Underflow is not found in Smart Contract.')
  })

  // Underflow condition found in Smart Contract
  it('Underflow condition is handled in If Statement another example', async () => {
    const underflowfile = 'tests/resources/Underflow/underflow12.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is not found in Smart Contract.')
  })

  // Underflow condition is handled in While Statement
  it('Underflow condition is handled in While Statement', async () => {
    const underflowfile = 'tests/resources/Underflow/underflow6.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 0, 'Vulnerability Underflow is found in Smart Contract.')
  })

  // Underflow condition found in While Statement
  it('Underflow condition found in While Statement', async () => {
    const underflowfile = 'tests/resources/Underflow/underflow8.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is found in Smart Contract.')
  })

  // Underflow condition is handled in For Statement
  it('Underflow condition handled in For Statement', async () => {
    const underflowfile = 'tests/resources/Underflow/underflow7.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 0, 'Vulnerability Underflow is found in Smart Contract.')
  })

  // Underflow condition found in For Statement
  it('Underflow condition found in For Statement', async () => {
    const underflowfile = 'tests/resources/Underflow/underflow9.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is found in Smart Contract.')
  })

  // Underflow condition found in Smart Contract with expression is a -= b
  it('Underflow condition found in Smart Contract with expression is a -= b', async () => {
    const underflowfile = 'tests/resources/Underflow/underflow15.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is not found in Smart Contract.')
  })

  // Underflow condition handled in Smart Contract with expression is a -= b
  it('Underflow condition handled in Smart Contract with expression is a -= b', async () => {
    const underflowfile = 'tests/resources/Underflow/underflow14.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_UNDERFLOW)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree, patterns)
    assert.equal(UnderflowFound[0], 0, 'Vulnerability Underflow is not found in Smart Contract.')
  })
})

describe('Test Overflow Vulnerability', () => {
  // Overflow condition found in Smart Contract
  it('Overflow condition found in Smart Contract', async () => {
    const overflowfile = 'tests/resources/Overflow/overflow3.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_OVERFLOW)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree, patterns)
    assert.equal(OverflowFound[0], 1, 'Vulnerability Overflow is not found in Smart Contract.')
  })

  it('should not detect vulnerability because compiler version > 0.8.0', async () => {
    const overflowFile = 'tests/resources/Overflow/overflow10.sol'
    const fileContents = file.readFileContents(overflowFile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_OVERFLOW)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree, patterns)
    assert.equal(OverflowFound[0], 0, 'Vulnerability Overflow was found in Smart Contract.')
  })

  // Overflow condition handled in Smart Contract
  it('Overflow condition handled in If condition for uint8', async () => {
    const overflowfile = 'tests/resources/Overflow/overflow1.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_OVERFLOW)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree, patterns)
    assert.equal(OverflowFound[0], 0, 'Vulnerability Overflow found in Smart Contract.')
  })

  // Overflow condition handled in Smart Contract
  it('Overflow condition handled in If condition for uint16', async () => {
    const overflowfile = 'tests/resources/Overflow/overflow5.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_OVERFLOW)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree, patterns)
    assert.equal(OverflowFound[0], 0, 'Vulnerability Overflow found in Smart Contract.')
  })

  // Overflow condition handled in While Loop
  it('Overflow condition handled in While Loop', async () => {
    const overflowfile = 'tests/resources/Overflow/overflow7.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_OVERFLOW)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree, patterns)
    assert.equal(OverflowFound[0], 0, 'Vulnerability Overflow found in Smart Contract.')
  })

  // Overflow condition found in While Loop
  it('Overflow condition found in While Loop', async () => {
    const overflowfile = 'tests/resources/Overflow/overflow8.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_OVERFLOW)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree, patterns)
    assert.equal(OverflowFound[0], 1, 'Vulnerability Overflow not found in Smart Contract.')
  })

  // Overflow condition found in For Loop
  it('Overflow condition found in For Loop', async () => {
    const overflowfile = 'tests/resources/Overflow/overflow9.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_OVERFLOW)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree, patterns)
    assert.equal(OverflowFound[0], 0, 'Vulnerability Overflow found in Smart Contract.')
  })

  // Overflow condition found in Smart Contract with expression a += b
  it('Overflow condition found in Smart Contract with expression a += b', async () => {
    const overflowfile = 'tests/resources/Overflow/overflow12.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_OVERFLOW)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree, patterns)
    assert.equal(OverflowFound[0], 1, 'Vulnerability Overflow is not found in Smart Contract.')
    console.log(OverflowFound[1])
  })

  // Overflow condition found in if condition in Smart Contract with expression a += b
  it('Overflow condition found in if condition in Smart Contract with expression a += b', async () => {
    const overflowfile = 'tests/resources/Overflow/overflow11.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const patterns = await db.retrievePatterns(vulnerabilities.INT_OVERFLOW)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree, patterns)
    assert.equal(OverflowFound[0], 1, 'Vulnerability Overflow is not found in Smart Contract.')
  })
})

describe('Test function that runs and aggregates the results of all vulnerability detectors', () => {
  it('should detect one floating pragma vulnerability and one reentrancy vulnerability', async () => {
    const solidityFile = 'tests/resources/vulnerabilityScanner/VulnerabilityScanner1.sol'
    const fileContents = file.readFileContents(solidityFile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const vulnerabilitiesDetected = await vulnerabilityScanner(parseTree)
    assert.equal(vulnerabilitiesDetected.length, 2)
    assert.equal(vulnerabilitiesDetected[0].vid, vulnerabilities.FLOATING_PRAGMA)
    assert.equal(vulnerabilitiesDetected[0].object.length, 1)

    assert.equal(vulnerabilitiesDetected[1].vid, vulnerabilities.REENTRANCY)
    assert.equal(vulnerabilitiesDetected[1].object.length, 1)
  })

  it('should detect one floating pragma vulnerability and one outdated compiler vulnerability', async () => {
    const solidityFile = 'tests/resources/vulnerabilityScanner/VulnerabilityScanner2.sol'
    const fileContents = file.readFileContents(solidityFile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const vulnerabilitiesDetected = await vulnerabilityScanner(parseTree)
    assert.equal(vulnerabilitiesDetected.length, 2)
    assert.equal(vulnerabilitiesDetected[0].vid, vulnerabilities.FLOATING_PRAGMA)
    assert.equal(vulnerabilitiesDetected[0].object.length, 1)

    assert.equal(vulnerabilitiesDetected[1].vid, vulnerabilities.OUTDATED_COMPILER_VERSION)
    assert.equal(vulnerabilitiesDetected[1].object.length, 1)
  })

  it('should detect one floating pragma vulnerability, one outdated compiler vulnerability, and one unchecked call return value vulnerability', async () => {
    const solidityFile = 'tests/resources/vulnerabilityScanner/VulnerabilityScanner3.sol'
    const fileContents = file.readFileContents(solidityFile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const vulnerabilitiesDetected = await vulnerabilityScanner(parseTree)
    assert.equal(vulnerabilitiesDetected.length, 3)
    assert.equal(vulnerabilitiesDetected[0].vid, vulnerabilities.FLOATING_PRAGMA)
    assert.equal(vulnerabilitiesDetected[0].object.length, 1)

    assert.equal(vulnerabilitiesDetected[1].vid, vulnerabilities.OUTDATED_COMPILER_VERSION)
    assert.equal(vulnerabilitiesDetected[1].object.length, 1)

    assert.equal(vulnerabilitiesDetected[2].vid, vulnerabilities.UNCHECKED_CALL_RETURN_VALUE)
    assert.equal(vulnerabilitiesDetected[2].object.length, 1)
  })

  it('should detect three tx.origin vulnerabilities and one hardcoded gas amount vulnerability', async () => {
    const solidityFile = 'tests/resources/vulnerabilityScanner/VulnerabilityScanner4.sol'
    const fileContents = file.readFileContents(solidityFile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const vulnerabilitiesDetected = await vulnerabilityScanner(parseTree)
    assert.equal(vulnerabilitiesDetected.length, 2)
    assert.equal(vulnerabilitiesDetected[0].vid, vulnerabilities.AUTH_THROUGH_TX_ORIGIN)
    assert.equal(vulnerabilitiesDetected[0].object.length, 3)

    assert.equal(vulnerabilitiesDetected[1].vid, vulnerabilities.HARDCODED_GAS_AMOUNT)
    assert.equal(vulnerabilitiesDetected[1].object.length, 1)
  })

  it('should detect one overflow vulnerability, one underflow vulnerability, one outdated compiler vulnerability, and one reentrancy vulnerability', async () => {
    const solidityFile = 'tests/resources/vulnerabilityScanner/VulnerabilityScanner5.sol'
    const fileContents = file.readFileContents(solidityFile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const vulnerabilitiesDetected = await vulnerabilityScanner(parseTree)
    assert.equal(vulnerabilitiesDetected.length, 4)

    assert.equal(vulnerabilitiesDetected[0].vid, vulnerabilities.INT_OVERFLOW)
    assert.equal(vulnerabilitiesDetected[0].object.length, 1)

    assert.equal(vulnerabilitiesDetected[1].vid, vulnerabilities.INT_UNDERFLOW)
    assert.equal(vulnerabilitiesDetected[1].object.length, 1)

    assert.equal(vulnerabilitiesDetected[2].vid, vulnerabilities.OUTDATED_COMPILER_VERSION)
    assert.equal(vulnerabilitiesDetected[2].object.length, 1)

    assert.equal(vulnerabilitiesDetected[3].vid, vulnerabilities.REENTRANCY)
    assert.equal(vulnerabilitiesDetected[3].object.length, 1)
  })

  it('should detect all seven of the detectable vulnerability types: ' +
      'two tx.origin vulnerabilities, one floating pragma vulnerability, ' +
      'one hardcoded gas amount vulnerability, one integer overflow vulnerability, ' +
      'one integer underflow vulnerability, one outdated compiler vulnerability, ' +
      'one reentrancy vulnerability, and one unchecked call return value vulnerability', async () => {
    const solidityFile = 'tests/resources/vulnerabilityScanner/VulnerabilityScannerAll.sol'
    const fileContents = file.readFileContents(solidityFile).toString()
    const parseTree = parser.parse(fileContents)
    await db.establishDbConnection()
    const vulnerabilitiesDetected = await vulnerabilityScanner(parseTree)
    assert.equal(vulnerabilitiesDetected.length, 8)

    assert.equal(vulnerabilitiesDetected[0].vid, vulnerabilities.AUTH_THROUGH_TX_ORIGIN)
    assert.equal(vulnerabilitiesDetected[0].object.length, 2)

    assert.equal(vulnerabilitiesDetected[1].vid, vulnerabilities.FLOATING_PRAGMA)
    assert.equal(vulnerabilitiesDetected[1].object.length, 1)

    assert.equal(vulnerabilitiesDetected[2].vid, vulnerabilities.HARDCODED_GAS_AMOUNT)
    assert.equal(vulnerabilitiesDetected[2].object.length, 1)

    assert.equal(vulnerabilitiesDetected[3].vid, vulnerabilities.INT_OVERFLOW)
    assert.equal(vulnerabilitiesDetected[3].object.length, 1)

    assert.equal(vulnerabilitiesDetected[4].vid, vulnerabilities.INT_UNDERFLOW)
    assert.equal(vulnerabilitiesDetected[4].object.length, 1)

    assert.equal(vulnerabilitiesDetected[5].vid, vulnerabilities.OUTDATED_COMPILER_VERSION)
    assert.equal(vulnerabilitiesDetected[5].object.length, 1)

    assert.equal(vulnerabilitiesDetected[6].vid, vulnerabilities.REENTRANCY)
    assert.equal(vulnerabilitiesDetected[6].object.length, 1)

    assert.equal(vulnerabilitiesDetected[7].vid, vulnerabilities.UNCHECKED_CALL_RETURN_VALUE)
    assert.equal(vulnerabilitiesDetected[7].object.length, 1)
  })
})
