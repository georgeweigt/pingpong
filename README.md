[Documentation](https://georgeweigt.github.io/pingpong.pdf)

#

To install `geth`

```
brew tap ethereum/ethereum
brew install ethereum
```

Create a directory `testnet` and initialize `geth`

```
mkdir testnet
cd testnet
geth --dev --datadir .
^C
```

To run `geth` normally

```
geth --goerli --nodiscover --allow-insecure-unlock --http --ws
```

In a separate terminal window, open the `geth` console

```
geth attach http://127.0.0.1:8545
```
