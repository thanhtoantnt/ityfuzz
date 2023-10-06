// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;


contract main {
    mapping(uint256 => uint256) knownsec;

    event AssertionFailed(string message);

    function process(uint256 a) public returns (string memory) {
        require(a > 200 && a < 210, "2");
        knownsec[2] = a;
        emit AssertionFailed("Bug");
        return "Hello Contracts";
    }
}
