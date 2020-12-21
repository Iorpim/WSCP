# WScp


Do you often need to transfer files around but is constantly harassed by annoying restrictive proxies?

So this project is for you! 

*WScp* is a state-of-the-art file transfer utility, it uses encrypted websocket communication to hide the fact that you are doing something you probably shouldn't.

Example usage:
```
$ go run main.go -p http://user:password@proxy.local -a -v 2 ws://site.web/api test.txt
     ..:: WScp ::..
[+] Sending: test.txt
[+] Destination: ws://site.web/api

 - Connecting to ws://site.web/api
 - Sending handshake message
 - Received valid handshake
 - Received valid AES key
 - Sending init message
 - Received valid encrypted response
 - Handshake completed

  10.50 Mb - 42 pkt |##################################################| 42 pkt - 10.50 Mb
```

Yes, it does come with a progress bar, free of charge

---
#### To do
##### Project
- [ ] Add build scripts
- [ ] Add install scripts
- [ ] Improve documentation
##### Server
- [ ] Add server config file
- [ ] Add server flags
- [ ] Improve server logging
- [ ] Add endpoint for file retrieval
##### Client
- [ ] Add client config file
- [ ] Add file download option
##### Transfer Package
- [ ] Improve binary marshaling in order to reduce footprint
##### Both
- [ ] Implement sync request for continuing failed transfers
- [ ] Make better comments