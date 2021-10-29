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
      assert.deepStrictEqual(pragmaStatement, { error: 'Smart contract must contain exactly one pragma directive.' })
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
      assert.deepStrictEqual(pragmaStatement, { error: 'Smart contract must contain exactly one pragma directive.' })
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

describe('Test Unchecked Call Return Value (SWC-104) Vulnerability', () => {
  it('should detect one unchecked call return value', () => {
    // Arrange
    const uncheckedCallReturnValueFilePath = 'tests/resources/UncheckedCallReturnValue.sol'
    const fileContents = file.readFileContents(uncheckedCallReturnValueFilePath).toString()
    const parseTree = parser.parse(fileContents)

    // Act
    const uncheckedCallReturnVulnerability = vulnerabilityDetectors.detectUncheckedCallReturnValue(parseTree)
    const vulnerabilityDetected = uncheckedCallReturnVulnerability[0] === true &&
        uncheckedCallReturnVulnerability[1].length === 1

    // Assert
    assert.equal(vulnerabilityDetected, true, 'Should return vulnerability found.')
  })

  it('should detect multiple unchecked call return values', () => {
    // Arrange
    const uncheckedCallReturnValuesFilePath = 'tests/resources/UncheckedCallReturnValues.sol'
    const fileContents = file.readFileContents(uncheckedCallReturnValuesFilePath).toString()
    const parseTree = parser.parse(fileContents)

    // Act
    const vulnerabilityDetected = vulnerabilityDetectors.detectUncheckedCallReturnValue(parseTree)

    // Assert
    assert.equal(vulnerabilityDetected[0], true, 'Should return multiple vulnerabilities found.')
  })

  it('should not detect unchecked call return value', () => {
    // Arrange
    const uncheckedCallReturnValuesFilePath = 'tests/resources/NoUncheckedCallReturnValue.sol'
    const fileContents = file.readFileContents(uncheckedCallReturnValuesFilePath).toString()
    const parseTree = parser.parse(fileContents)

    // Act
    const vulnerabilityDetected = vulnerabilityDetectors.detectUncheckedCallReturnValue(parseTree)

    // Assert
    assert.equal(vulnerabilityDetected[0], false, 'Should return no vulnerabilities found.')
  })
})

describe('Test TX Origin Vulnerability', () => {
  it('should detect tx.origin in if statement and require statement', () => {
    const txoriginfile = 'tests/resources/Tx.origin/txorigin1.sol'
    const fileContents = file.readFileContents(txoriginfile).toString()
    const parseTree = parser.parse(fileContents)
    const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree)
    assert.equal(TxOriginFound.length, 2, 'Vulnerability TX.Origin is not found in Smart Contract.')
  })

  // Detect tx.origin which is declared in Require statement. eg. require(tx.origin == owner)
  it('Detect TX.Origin in Require Statement. eg. require(tx.origin == msg.sender)', () => {
    const txoriginfile = 'tests/resources/Tx.origin/txorigin2.sol'
    const fileContents = file.readFileContents(txoriginfile).toString()
    const parseTree = parser.parse(fileContents)
    const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree)
    assert.equal(TxOriginFound.length, 3, 'Vulnerability TX.Origin is found in Smart Contract')
  })

  // // Tx.origin is not mentioned in smart contract
  it('Detect TX.Origin is not found in Smart Contract', () => {
    const txoriginfile = 'tests/resources/Tx.origin/txorigin3.sol'
    const fileContents = file.readFileContents(txoriginfile).toString()
    const parseTree = parser.parse(fileContents)
    const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree)
    assert.equal(TxOriginFound.length, 0, 'Vulnerability TX.Origin is found in Smart Contract')
  })

  // Detect tx.origin which is declared in If statement and assignment of Tx.origin is in right side. eg. if(owner == tx.origin)
  it('Detect TX.Origin in If Statement and assignment is Right Side in If Statement. eg. if(owner == tx.origin)', () => {
    const txoriginfile = 'tests/resources/Tx.origin/txorigin4.sol'
    const fileContents = file.readFileContents(txoriginfile).toString()
    const parseTree = parser.parse(fileContents)
    const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree)
    assert.equal(TxOriginFound.length, 1, 'Vulnerability TX.Origin is not found in Smart Contract')
  })
})

describe('Test Underflow Vulnerability', () => {
  // Underflow condition found in Smart Contract
  it('Underflow condition found in Smart Contract', () => {
    const underflowfile = 'tests/resources/Underflow/underflow1.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is not found in Smart Contract.')
  })

  it('should not detect vulnerability because compiler version > 0.8.0', () => {
    const underflowFile = 'tests/resources/Underflow/underflow13.sol'
    const fileContents = file.readFileContents(underflowFile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound[0], 0, 'Vulnerability Underflow was found in Smart Contract.')
  })

  // Underflow condition found in Smart Contract
  it('Underflow condition is handled in If Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow2.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is found in Smart Contract.')
  })

  // Underflow condition found in Smart Contract
  it('Underflow condition found in If Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow10.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is not found in Smart Contract.')
  })

  // Underflow condition is handled in If Statement
  it('Underflow condition is handled in If Statement with multiple condition', () => {
    const underflowfile = 'tests/resources/Underflow/underflow11.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound[0], 0, 'Vulnerability Underflow is not found in Smart Contract.')
  })

  // Underflow condition found in Smart Contract
  it('Underflow condition is handled in If Statement another example', () => {
    const underflowfile = 'tests/resources/Underflow/underflow12.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is not found in Smart Contract.')
  })

  // Underflow condition is handled in While Statement
  it('Underflow condition is handled in While Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow6.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound[0], 0, 'Vulnerability Underflow is found in Smart Contract.')
  })

  // Underflow condition found in While Statement
  it('Underflow condition found in While Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow8.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is found in Smart Contract.')
  })

  // Underflow condition is handled in For Statement
  it('Underflow condition handled in For Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow7.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound[0], 0, 'Vulnerability Underflow is found in Smart Contract.')
  })

  // Underflow condition found in For Statement
  it('Underflow condition found in For Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow9.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound[0], 1, 'Vulnerability Underflow is found in Smart Contract.')
  })
})

describe('Test Overflow Vulnerability', () => {
  // Overflow condition found in Smart Contract
  it('Overflow condition found in Smart Contract', () => {
    const overflowfile = 'tests/resources/Overflow/overflow3.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound[0], 1, 'Vulnerability Overflow is not found in Smart Contract.')
  })

  it('should not detect vulnerability because compiler version > 0.8.0', () => {
    const overflowFile = 'tests/resources/Overflow/overflow10.sol'
    const fileContents = file.readFileContents(overflowFile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound[0], 0, 'Vulnerability Overflow was found in Smart Contract.')
  })

  // Overflow condition handled in Smart Contract
  it('Overflow condition handled in If condition for uint8', () => {
    const overflowfile = 'tests/resources/Overflow/overflow1.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound[0], 0, 'Vulnerability Overflow found in Smart Contract.')
  })

  // Overflow condition handled in Smart Contract
  it('Overflow condition handled in If condition for uint16', () => {
    const overflowfile = 'tests/resources/Overflow/overflow5.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound[0], 0, 'Vulnerability Overflow found in Smart Contract.')
  })

  // Overflow condition handled in While Loop
  it('Overflow condition handled in While Loop', () => {
    const overflowfile = 'tests/resources/Overflow/overflow7.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound[0], 0, 'Vulnerability Overflow found in Smart Contract.')
  })

  // Overflow condition found in While Loop
  it('Overflow condition found in While Loop', () => {
    const overflowfile = 'tests/resources/Overflow/overflow8.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound[0], 1, 'Vulnerability Overflow not found in Smart Contract.')
  })

  // Overflow condition found in For Loop
  it('Overflow condition found in For Loop', () => {
    const overflowfile = 'tests/resources/Overflow/overflow9.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound[0], 0, 'Vulnerability Overflow found in Smart Contract.')
  })
})
