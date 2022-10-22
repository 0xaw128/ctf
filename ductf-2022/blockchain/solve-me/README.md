# Solve Me [beginner]

description:

"Aight warm up time. All you gotta do is call the solve function. You can do it!"

given:
- solidity file
- instance (RPC URL)

The goal is solve function is external, and it changes the value of a boolean to true, so we need to change the state of the blockchain.

First the `SolveMe.sol` was compiled into bytecode using `solc`

```sh
solcjs --abi SolveMe.sol
```

We call `buildTransaction` to build the transaction based on the specified contract and make changes to the blockchain, sign, then send it. After this has been sent, the state of the blockchain has been changed and the flag can be accessed.
