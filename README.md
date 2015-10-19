# ndispktscan
NDISPktScan is a plugin for the [Volatility Framework](https://github.com/volatilityfoundation/volatility). It parses the Ethernet packets stored by [ndis.sys](https://technet.microsoft.com/en-gb/library/cc958797.aspx) in Windows kernel space memory.

## How does it work?
The [Network Driver Interface Specification](https://en.wikipedia.org/wiki/Network_Driver_Interface_Specification) is an API for network cards used by Windows (and other OSs). On Windows, the API is implemented by ndis.sys which is a [Kernel Mode driver](https://msdn.microsoft.com/en-us/library/windows/hardware/ff554836%28v=vs.85%29.aspx).

An Ethernet packet, or, depending on the version of Windows, the start of an Ethernet packet, can be found by searching kernel memory space for a source MAC address followed by an [EtherType](https://en.wikipedia.org/wiki/EtherType) of IPv4 or IPv6. As long as the source MAC address is known, the packets can be found and recovered.

Ideally, the source MAC address will be passed to the plugin via the `--mac` switch (see below).

For NDIS 6.20, the version used by Windows 7 and Windows Server 2008R2, the plugin can detect the MAC address by parsing data around what seems to be a [pool tag](http://blogs.technet.com/b/yongrhee/archive/2009/06/24/pool-tag-list.aspx) of `NDsh`.

## What information can it get?
The plugin will output at least the source and destination MAC addresses and the EtherType of any found packets. If the packet is TCP or UDP over IPv4 or IPv6 (as they often are) the plugin will also output the source and destination IP addresses, the source and destination port numbers, and, for TCP, the TCP flags. The packets can optionally be saved to a PCAP file via the `--pcap` switch (see below).

For those with an especially forensic interest, consider the `--slack` option. Entries in the NDIS cache (if that is indeed what it is) seem to be reused, meaning that if the new data is fewer bytes than what was previously at that position in memory, there is likely slack. The `--slack` option will output only "sensible" data recovered from slack. Typically these will be hostnames.

In both cases, if an [encoded NetBIOS hostname](https://support.microsoft.com/en-gb/kb/194203) is found, it will be presented encoded, followed by the decoded version in brackets.

## How do I use it?
### Let Volatility know you're using an additional plugin.
Use the `--plugins` switch to specify the folder containing any additional plugins you wish Volatility to load:
```
$ vol.py --plugins=path/to/ndispktscan -f memory.dmp --profile=Win7SP1x64 ndispktscan
```
### Switches
#### --pcap/-p
Each found packet will be saved to the PCAP file you specify. The file can then be used by the tool of your choice, for example, [WireShark](https://www.wireshark.org/).
#### --dsts/-D
Each target IP address will be saved to the text file you specify; duplicates will be removed.
#### --slack/-s
Look for sensible slack data. Typically hostnames found beyond the current packet.
#### --mac/-m
Search for this source MAC address. Provide mac address as: `--mac a1B2c3D4e5F6` or `--mac a1:B2:c3:D4:e5:F6`. (Capitalisation doesn't matter.)

## Note
As the NDIS driver has developed over time, that is, through the different versions of Windows, the amount of the packet seen in kernel space seems to have reduced. For example, in Windows XP, a full GET request can be seen in a packet, in Windows 7, the TCP header is present, but no payload, and in Windows 10, the TCP header seems incomplete. That said, there is still a lot of useful information that can be discerned and WireShark does an excellent job of presenting the data as best it can.

## Sample Output 1
`$ vol.py --plugins path/to/ndispktscan/ -f memory.dmp --profile Win7SP1x64 ndispktscan --pcap out.pcap --dsts ips.txt`
```
Offset (V)         Source MAC        Destination MAC   Prot Source IP                               Destination IP                          SPort DPort Flags
------------------ ----------------- ----------------- ---- --------------------------------------- --------------------------------------- ----- ----- -----
0x0000f6fd40017ff8 00:0C:29:84:88:F6 00:50:56:E4:93:7D 0x06 172.16.129.130                          37.252.162.10                           49179    80 ACK
0x0000fa8002d5dff8 00:0C:29:84:88:F6 33:33:00:00:00:02 0x3a fe80:0:0:0:f8f5:b255:243f:187           ff02:0:0:0:0:0:0:2                      Proto NotKn own
0x0000fa8002d5eff8 00:0C:29:84:88:F6 33:33:00:00:00:16 0x00 fe80:0:0:0:f8f5:b255:243f:187           ff02:0:0:0:0:0:0:16                     Proto NotKn own
0x0000fa8002d5fff8 00:0C:29:84:88:F6 33:33:00:00:00:16 0x00 fe80:0:0:0:f8f5:b255:243f:187           ff02:0:0:0:0:0:0:16                     Proto NotKn own
0x0000fa8002d60ff8 00:0C:29:84:88:F6 00:50:56:E4:93:7D 0x11 172.16.129.130                          172.16.129.2                            63506    53 ---
0x0000fa8002d62ff8 00:0C:29:84:88:F6 00:50:56:E4:93:7D 0x06 172.16.129.130                          93.184.220.29                           49192    80 ACK
0x0000fa8002d63ff8 00:0C:29:84:88:F6 33:33:00:01:00:03 0x11 fe80:0:0:0:f8f5:b255:243f:187           ff02:0:0:0:0:0:1:3                      60209  5355 ---
--SNIP--
0x0000fa8002d64ff8 00:0C:29:84:88:F6 00:50:56:E4:93:7D 0x06 172.16.129.130                          23.38.75.69                             49190    80 ACK
0x0000fa8003099ff8 00:0C:29:84:88:F6 00:50:56:E4:93:7D 0x06 172.16.129.130                          23.63.99.225                            49166    80 ACK
Found 426 packets from 1 MACs.
Written 426 records (31,569 bytes) to 'out.pcap'.
Written 35 destination IPs to 'ips.txt'.
```
## Sample Output 2
`$ vol.py --plugins path/to/ndispktscan/ -f memory.dmp --profile Win7SP1x64 ndispktscan --slack`
```
Offset (V)         Slack Data
------------------ ----------
0x0000fa8002d64ff8 1.....n.............memtest-PC
0x0000fa8002dd8ff8 T..s...........memtest-PC
0x0000fa8002dd9ff8 memtest-PC
0x0000fa8002ddaff8 isatap.localdomain
0x0000fa8002dddff8 ENEFENFEEFFDFECNFAEDCACACACACACA (MEMTEST-PC)
0x0000fa8002de3ff8 memtest-PC
0x0000fa8002de8ff8 FHEPFCELEHFCEPFFFACACACACACACAAA (WORKGROUP)
0x0000fa8002de9ff8 ENEFENFEEFFDFECNFAEDCACACACACAAA (MEMTEST-PC)
0x0000fa8002df0ff8 uyv...........memtest-PC
0x0000fa8002df1ff8 memtest-PC
0x0000fa8002df4ff8 wpad.localdomain
0x0000fa8002df6ff8 wpad
0x0000fa8002df7ff8 teredo.ipv6.microsoft.com
0x0000fa8002df8ff8 uyv...........memtest-PC
--SNIP--
0x0000fa8002e78ff8 ENEFENFEEFFDFECNFAEDCACACACACAAA (MEMTEST-PC)
0x0000fa8002e79ff8 FHEPFCELEHFCEPFFFACACACACACACAAA (WORKGROUP)
0x0000fa8002e7fff8 FHFAEBEECACACACACACACACACACACAAA (WPAD)
0x0000fa8002e80ff8 www.msftncsi.com
0x0000fa8002f0aff8 go.microsoft.com
0x0000fa8002f0bff8 www.msn.com
0x0000fa8002f22ff8 static-hp-neu.s-msn.com
0x0000fa8002f58ff8 b.scorecardresearch.com
0x0000fa8002f5aff8 otf.msn.com
0x0000fa8002f5bff8 img-s-msn-com.akamaized.net
0x0000fa8002f7cff8 c.bing.com
0x0000fa8002fe5ff8 cdn.adnxs.com
Found 44 "sensible" slack items.
```
## Sample Output 3
`$ vol.py --plugins path/to/ndispktscan/ -f memory.dmp --profile Win8SP1x86 ndispktscan --mac 000c29838725`
```
Offset (V) Source MAC        Destination MAC   Prot Source IP                               Destination IP                          SPort DPort Flags
---------- ----------------- ----------------- ---- --------------------------------------- --------------------------------------- ----- ----- -----
0x85907452 00:0C:29:83:87:25 00:50:56:E4:93:7D 0x06 172.16.129.129                          65.55.138.111                           49171   443 ACK
0x8590c45a 00:0C:29:83:87:25 00:50:56:E4:93:7D 0x06 172.16.129.129                          65.55.138.111                           49171   443 ACK
0x85913222 00:0C:29:83:87:25 00:50:56:E4:93:7D 0x06 172.16.129.129                          157.55.240.126                          49177   443 ACK,PSH
0x85979fba 00:0C:29:83:87:25 00:50:56:E4:93:7D 0x06 172.16.129.129                          65.55.138.111                           49171   443 ACK
0x8598037a 00:0C:29:83:87:25 00:50:56:E4:93:7D 0x06 172.16.129.129                          65.55.138.111                           49171   443 ACK
0x85982fba 00:0C:29:83:87:25 00:50:56:E4:93:7D 0x06 172.16.129.129                          23.43.75.27                             49167    80 ACK,RST
0x85985222 00:0C:29:83:87:25 00:50:56:E4:93:7D 0x06 172.16.129.129                          65.55.138.111                           49171   443 ACK`
--SNIP--
0x88b86aba 00:0C:29:83:87:25 00:50:56:E4:93:7D 0x06 172.16.129.129                          157.56.194.72                           49410   443 ACK
0x88b9965a 00:0C:29:83:87:25 00:50:56:E4:93:7D 0x06 172.16.129.129                          23.67.255.203                           49419    80 ACK,PSH
Found 97 packets from 1 MACs.
```
