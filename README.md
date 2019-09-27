# Tsuru

## Idea

1. Read pcap file, skipping the pcap global header.
2. Incrementally read the packet. From packet header, get the length of the packet (for offset)
3. Peek inside payload, check if this payload is a UDP packet or not via UDP header length and offset.
4. Consume quote market data and save in records.
5. Process next packet...

## Optimizations

1. Can try async/await to push quote market data into list (and then we can sort using timestamp or order given)
2. Can try [rank-select bit-string](https://haskell-works.github.io/posts/2018-08-01-introduction-to-rank-select-bit-string.html)? (But it seems it is skeptical to improve much because we did not have a complex enum data type that requires a lot of memory allocation.)
