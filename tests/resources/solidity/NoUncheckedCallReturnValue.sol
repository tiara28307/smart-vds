/*
    Name: Ti'Ara Carroll
    Due Date: 09/20/21
    Assignment 1
*/

// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.7;

contract PayRent {
    // initialize variable(s)
    uint256 monthlyRent;

    // runs when contract is executed
    // initializes contract state
    constructor() {
        monthlyRent = 500;
    }

    // subscriber able to make payment to account
    function makePayment() payable public {}

    // check the current balance of the account
    function getCurrentBalance() public view returns (uint256 balance) {
        return address(this).balance;
    }

    // check if subscriber is up to date on their rent
    function isRentUpToDate(uint256 monthsPassed) public view returns (bool) {
        return monthlyRent * monthsPassed == address(this).balance;
    }

    // withdraw money (ether) from account
    function withdrawBalance() public {
        payable(msg.sender).transfer(address(this).balance);
    }

}