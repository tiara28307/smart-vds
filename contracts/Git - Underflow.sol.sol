/**
Vulnerability - Integer Underflow (SWC-101)

URL - https://github.com/punishell/SmartContracts/blob/main/HelloWorldBank.sol
**/

pragma solidity 0.6.6;

contract HelloWorldBank {
    address public owner; // public address variable 
    mapping(address => uint) private balances;// mapping address with uint balances
    
    constructor()public payable{ //konstruktor tworzony jest gdy smart contract jest zdeplojownay 
    owner = msg.sender; // sender of the message (current call) during the constructor it is always owner who deployed the contract
    
    }
    function isOwner() public view returns(bool){
        return msg.sender == owner; // here we call function that compaer the previous called msg.sender and savce it in owner wit current msg.sender  
        
    }
    modifier onlyOwner(){ //modifier is a special function that modifies behavior of the function
        require(isOwner());
        _; 
    }
    function deposit() public payable{
        require((balances[msg.sender] + msg.value) >=balances[msg.sender]);
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint withdrawAmount) public {
        require(withdrawAmount <= balances[msg.sender]);
        
        balances[msg.sender] -=  withdrawAmount;
        msg.sender.transfer(withdrawAmount); 
        
    }
    function withdrawAll() public onlyOwner{ //calling modifier here which check isOwner before to call functions
        msg.sender.transfer(address(this).balance);
        
    }
    function getBalance() public view returns(uint){
        return balances[msg.sender];
    }
}