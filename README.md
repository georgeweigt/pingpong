`pingpong` communicates with a local `geth` process over the loopback interface 127.0.0.1

This project is under construction.
Currently the `auth/ack` message exchange is working.

See the directory `src` for individual source files.
`pingpong.c` is the cat of source files from `src`

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

# Lessons learned

1. AUTH and ACK messages have the following format.

```
prefix || R || ciphertext || hmac
```

Note that `R` is an ephemeral public key that the receiver uses to verify `hmac` and decrypt the ciphertext.
After decryption, `R` is thrown away and is not used for anything else.
In particular, `R` is not used to compute any session secrets.

2. `hmac` computation includes the prefix as follows.

```
hmac = hmac256(ciphertext || prefix)
```

3. After decryption we have

```
prefix || R || iv || msg || hmac
```

The ciphertext of `iv || msg` is not padded to form a multiple of 16 byte blocks as is done in TLS and VPN.
Hence the length of ciphertext is exactly the same as the length of `iv || msg`.

4. From RLPx documentation

```
auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
ack-body = [recipient-ephemeral-pubk, recipient-nonce, ack-vsn, ...]
```

Note that we have `recipient-ephemeral-pubk` but no `initiator-ephemeral-pubk` is shown.
Of course, both are required to establish a shared secret.
It turns out that `initiator-ephemeral-pubk` is recovered from `sig`.

#

[Documentation](https://georgeweigt.github.io/pingpong.pdf)
