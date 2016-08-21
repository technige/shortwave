# Shortwave

**CAUTION: Alpha and Linux-only right now!**

Shortwave is a library of components for Python network applications.
It has been put together from separate modules, libraries and applications that I have worked on over the years.

The library is currently only alpha quality but is coming together quickly.
Much of the pre-existing code is well tested and the job is to bring these parts together as a coherent whole.

So far, Shortwave consists of the following:


## `shortwave.transmission`

Low-level components for TCP communication.
This layer sits just above raw sockets.
It hosts a synchronous `Transmitter` and an asynchronous `Receiver` that are brought together within an extensible `Connection` object.


## `shortwave.messaging`

An implementation of RFC 822 plus some other utilities for network messaging.


## `shortwave.http`

An implementation of RFC 2616 (client).


## `shortwave.uri`

An implementation of RFC 3986.


----


**TODO: Lots. Working on it.**
