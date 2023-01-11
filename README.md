`pingpong` communicates with a local `geth` process over the loopback interface 127.0.0.1

The code is under construction. Currently the `auth/ack` message exchange is working.

#

To build and run

```
make
./pingpong
```

To run a self test

```
./pingpong test
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

`geth` prints its public key on start up

```
self="enode://1ecbbdb04f54b68d99a9fb0d60786d29164ffe9776bad9118ec896f2764ec9f711ec2e6f8e0e21c1f0f9abe4515c45949e6bf776d84b54d08f7c32de60e8c480@127.0.0.1:30303?discport=0"
```

In `pingpong.c`, set `GETH_PUBLIC_KEY` accordingly and run `make`

```
#define GETH_PUBLIC_KEY "1ecbbdb04f54b68d99a9fb0d60786d29164ffe9776bad9118ec896f2764ec9f711ec2e6f8e0e21c1f0f9abe4515c45949e6bf776d84b54d08f7c32de60e8c480"
```

#

[Documentation](https://georgeweigt.github.io/pingpong.pdf)

