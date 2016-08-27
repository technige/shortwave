![Shortwave](www/shortwave-pixels-black.png)

----

**CAREFUL NOW! This library is not yet ready for production use and currently only works on Linux systems that provide *epoll*.**

----

Shortwave is a library of components for Python network applications.
It has been put together from separate modules, libraries and applications that I have worked on over the years.

The library is coming together quickly.
Much of the pre-existing code is well tested and the job is to bring these parts together as a coherent whole.

So far, Shortwave consists of the following:


## `shortwave.transmission`

Low-level components for TCP communication.
This layer sits just above raw sockets.
It hosts a synchronous `Transmitter` and an asynchronous `Receiver` that are brought together within an extensible `Connection` object.


## `shortwave.messaging`

An implementation of RFC 822 plus some other utilities for network messaging.


## `shortwave.http`

An HTTP client implementation.


## `shortwave.uri`

A collection of URI and URI template functions as described by RFCs 3986 and 6570.


----

**TODO: Lots. Working on it.**

----

## Command Line Usage

Install the command line interface by running `python setup.py develop`.

### GET a web page

```
shortwave.http get -v http://shortwave.tech/hello
```

### POSTing data

```
shortwave.http post -j -v http://shortwave.tech/json '{"greeting": "hello, world"}'
```
