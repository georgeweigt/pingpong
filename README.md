[Documentation](https://georgeweigt.github.io/pingpong.pdf)

#

To build and run

```
make
./pingpong
```

#

To install `geth`

```
brew tap ethereum/ethereum
brew install ethereum
```

To run `geth`

```
geth --goerli --nodiscover --allow-insecure-unlock --http --ws --verbosity 5
```

When geth starts it prints its public key

```
INFO [01-11|15:05:52.707] Started P2P networking                   self="enode://1ecbbdb04f54b68d99a9fb0d60786d29164ffe9776bad9118ec896f2764ec9f711ec2e6f8e0e21c1f0f9abe4515c45949e6bf776d84b54d08f7c32de60e8c480@127.0.0.1:30303?discport=0"
```

In `pingpong.c`, set `GETH_PUBLIC_KEY` accordingly

```
#define GETH_PUBLIC_KEY "1ecbbdb04f54b68d99a9fb0d60786d29164ffe9776bad9118ec896f2764ec9f711ec2e6f8e0e21c1f0f9abe4515c45949e6bf776d84b54d08f7c32de60e8c480"
```
