## Description

DNS Adblocker used to block ads, malicious links, unwanted sites and etc..

## Run

```bash
dns-adblocker server
```

## Testing

add `ads.doubleclick.net` to data/blacklist.txt and run this

```bash
nslookup ads.doubleclick.net 127.0.0.1
```


## TODO
- in-meomry inbound response caching
- connection pooling
- use radix/trie for efficient lookups blacklist
