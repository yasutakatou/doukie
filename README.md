# doukie

**multi platform, one binary, automated file transfer util by Golang**.
doukie is meaned japanese word is "sync", and green day's album "dookie" anagramed.

# demo

(WIP)

# solution

AirDrop is very useful file transfer method.
But, It's not what I'd expect opened economy method.
on not supported computers, is require support by official or OSS comunity effort.

**We know universal protocol, is HTTP**.

I think to want implement easy file transfer method by HTTP.
and, I realize file transfer on multi platform (include Smart phone!).

# features

 - multi platform suppoted
 - run by one binary file
 - Android supported (it's not perfect)
 - automated file transfer.
 - file exists check (use md5 hash)

# usecase

## case1: PC Client and PC Server (or vice versa)
 - use static token authentication
    this mode, you set static token when tool running, and client side same token.
    client access to server by static token.
    in case of authentication success, client copy files from server.
 - auto sync mode
    server send multicast udp packet periodically include authentication detail.
    when client receive this packet, decrypt packet, client start to access to server.
    **I mean, You don't need to know the server's IP address!**
    in case of authentication success, client copy files from server.

## case2: PC Server and Android Client
 - QR code scan and access to server
    When start application, QR code scan displayed.
    server console display QR code and scan by Android.
    in case of authentication success, Android copy files from server.

## case3: Android(server) to PC(client)
  This feature is not implemented.

# installation

If you want to put it under the path, you can use the following.

```
go get github.com/yasutakatou/doukie
```

If you want to create a binary and copy it yourself, use the following.

```
git clone https://github.com/yasutakatou/doukie
cd doukie
go build doukie.go
```

[or download binary from release page]().
save binary file, copy to entryed execute path directory.

# uninstall

delete that binary. del or rm command. (it's simple!)

# usecase details

## case1: PC(server) to PC(client)
 - use static token authentication

when static token mode, you set static token when running.
this following token is "test".

```
doukie -token=test
```

note) If not set static token, tool create and use random 8 character.

next, client side, set server ip address and token.

```
doukie -token=test -dst=192.168.0.1
```

note) server's ip is must examine before running.

 - auto sync mode

this mode only set token used encrypt and decrypt.

note )  If can decrypt udp packet from server, access server data. 
 this mode danger and recommend in home and trust network use only.

```
doukie -auto=test
```

next, set same token to client, too.

```
doukie -autoDst=test
```

### You want to use another feature.

 - transfer by HTTPS.

```
doukie -https -cert=localhost.pem -key=localhost-key.pem -token=test
```

note) you have to prepare certs.

 - change target directory.

```
doukie -dir=myDir -token=test -dst=192.168.0.1
```

 - by default if some file exists client, but not exists server, that file delete on client.
    when enable -noDelete option, not delete.

```
doukie -noDelete -token=test -dst=192.168.0.1
```

See here for other options.

## case2: PC(server) to Android(client)
 - QR code scan and access to server

look at andoukie(doukie client for Android).
what is andoukie? here.

# options

this options enable on only PC. Android not useful.

|option name|default value|detail|
|:---|:---|:---|
-auto||auto sync server mode enable and set encrypt token.|
-autoPort|9999|port number for auto sync mode.|
-autoDst||auto sync client mode enable and set decrypt token.|
-dst||client mode enable and set access url.|
-wait|10|sync duration. (Second)|
-dir|data|sync target directory|
-debug|false|debug mode (true is enable)|
-https|false|https mode (true is enable)|
-token||authentication token (if this value is null, is set random)|
-port|8080|port number|
-cert|localhost.pem|ssl_certificate file path (if you don't use https, haven't to use this option)|
-key|localhost-key.pem|ssl_certificate_key file path (if you don't use https, haven't to use this option)|
-notDelete|false|not delete mode (true is enable)|
