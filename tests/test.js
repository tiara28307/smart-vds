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

describe('Test TX Origin Vulnerability', () => {

  //Detect tx.origin which is declared in If statement and assignment of Tx.origin is in left side. eg. if(tx.origin == owner)
  it('Detect TX.Origin in If Statement and assignment is Left Side in If Statement. eg. if(tx.origin == owner)', () => {
    const txoriginfile = 'tests/resources/Tx.origin/txorigin1.sol'
    const fileContents = file.readFileContents(txoriginfile).toString()
    const parseTree = parser.parse(fileContents)
    const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree)
    assert.equal(TxOriginFound, 1, 'Vulnerability TX.Origin is not found in Smart Contract.')
  })

  //Detect tx.origin which is declared in Require statement. eg. require(tx.origin == owner)
  it('Detect TX.Origin in Require Statement. eg. require(tx.origin == msg.sender)', () => {
     const txoriginfile = 'tests/resources/Tx.origin/txorigin2.sol'
     const fileContents = file.readFileContents(txoriginfile).toString()
     const parseTree = parser.parse(fileContents)
     const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree)
     assert.equal(TxOriginFound, 1, 'Vulnerability TX.Origin is found in Smart Contract')
  })

  //Tx.origin is not mentioned in smart contract
  it('Detect TX.Origin is not found in Smart Contract', () => {
     const txoriginfile = 'tests/resources/Tx.origin/txorigin3.sol'
     const fileContents = file.readFileContents(txoriginfile).toString()
     const parseTree = parser.parse(fileContents)
     const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree)
     assert.equal(TxOriginFound, 0, 'Vulnerability TX.Origin is found in Smart Contract')
  })

  //Detect tx.origin which is declared in If statement and assignment of Tx.origin is in right side. eg. if(owner == tx.origin)
  it('Detect TX.Origin in If Statement and assignment is Right Side in If Statement. eg. if(owner == tx.origin)', () => {
     const txoriginfile = 'tests/resources/Tx.origin/txorigin4.sol'
     const fileContents = file.readFileContents(txoriginfile).toString()
     const parseTree = parser.parse(fileContents)
     const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree)
     assert.equal(TxOriginFound, 1, 'Vulnerability TX.Origin is not found in Smart Contract')
  })

  //Detect tx.origin is used to assign as the owner of the smart contract
  it('Detect TX.Origin in Smart contract which is used as assignment to the owner of the contract. eg. owner = tx.origin', () => {
     const txoriginfile = 'tests/resources/Tx.origin/txorigin7.sol'
     const fileContents = file.readFileContents(txoriginfile).toString()
     const parseTree = parser.parse(fileContents)
     const TxOriginFound = vulnerabilityDetectors.detectTXOrigin(parseTree)
     assert.equal(TxOriginFound, 1, 'Vulnerability TX.Origin is not found in Smart Contract')
  })
})

describe('Test Underflow Vulnerability', () => {

  //Underflow condition found in Smart Contract
  it('Underflow condition found in Smart Contract', () => {
    const underflowfile = 'tests/resources/Underflow/underflow1.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound, 1, 'Vulnerability Underflow is not found in Smart Contract.')
  })

  //Underflow condition is handled in If Statement
  it('Underflow condition is handled in If Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow2.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound, 0, 'Vulnerability Underflow is found in Smart Contract.')
  })

  //Underflow condition is handled in Require Statement
  it('Underflow condition is handled in Require Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow3.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound, 0, 'Vulnerability Underflow is found in Smart Contract.')
  })

  //Underflow condition is handled using Safemath Library
  it('Underflow condition is handled using Safemath Library', () => {
    const underflowfile = 'tests/resources/Underflow/underflow4.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound, 0, 'Vulnerability Underflow is found in Smart Contract.')
  })

  //Underflow condition is handled in While Statement
  it('Underflow condition is handled in While Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow6.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound, 0, 'Vulnerability Underflow is found in Smart Contract.')
  })

  //Underflow condition found in While Statement
  it('Underflow condition found in While Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow8.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound, 1, 'Vulnerability Underflow is found in Smart Contract.')
  })

  //Underflow condition is handled in For Statement
  it('Underflow condition handled in For Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow7.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound, 0, 'Vulnerability Underflow is found in Smart Contract.')
  })

  //Underflow condition found in For Statement
  it('Underflow condition found in For Statement', () => {
    const underflowfile = 'tests/resources/Underflow/underflow9.sol'
    const fileContents = file.readFileContents(underflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const UnderflowFound = vulnerabilityDetectors.detectUnderFlow(parseTree)
    assert.equal(UnderflowFound, 1, 'Vulnerability Underflow is found in Smart Contract.')
  })
})

describe('Test Overflow Vulnerability', () => {

  //Overflow condition found in Smart Contract
  it('Underflow condition found in Smart Contract', () => {
    const overflowfile = 'tests/resources/Overflow/overflow3.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound, 1, 'Vulnerability Overflow is not found in Smart Contract.')
  })

  //Overflow condition handled in Smart Contract
  it('Overflow condition handled in Smart Contract', () => {
    const overflowfile = 'tests/resources/Overflow/overflow1.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound, 0, 'Vulnerability Overflow found in Smart Contract.')
  })

  //Overflow condition handled in Smart Contract
  it('Overflow condition handled in Smart Contract', () => {
    const overflowfile = 'tests/resources/Overflow/overflow5.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound, 0, 'Vulnerability Overflow found in Smart Contract.')
  })

  //Overflow condition handled in Require Statement
  it('Overflow condition handled in Require Statement', () => {
    const overflowfile = 'tests/resources/Overflow/overflow6.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound, 0, 'Vulnerability Overflow found in Smart Contract.')
  })

  //Overflow condition handled in While Loop
  it('Overflow condition handled in While Loop', () => {
    const overflowfile = 'tests/resources/Overflow/overflow7.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound, 0, 'Vulnerability Overflow found in Smart Contract.')
  })

  //Overflow condition found in While Loop
  it('Overflow condition found in While Loop', () => {
    const overflowfile = 'tests/resources/Overflow/overflow8.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound, 1, 'Vulnerability Overflow not found in Smart Contract.')
  })

  //Overflow condition found in For Loop
  it('Overflow condition found in For Loop', () => {
    const overflowfile = 'tests/resources/Overflow/overflow9.sol'
    const fileContents = file.readFileContents(overflowfile).toString()
    const parseTree = parser.parse(fileContents)
    const OverflowFound = vulnerabilityDetectors.detectOverFlow(parseTree)
    assert.equal(OverflowFound, 1, 'Vulnerability Overflow not found in Smart Contract.')
  })
})