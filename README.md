# excessive-acl
App correlates syslog messages emitted by a Cisco ASA against access-lists applied to interfaces

## Use case
Identification of ACL-entries that are over-permissive based on past traffic. 

Before creating the app I was challenged with above use case. By that time there were two main approaches:
- check hitcounts from  `show access-list <name>`. This approach doesn't reveal which ACL-entries are open too wide.
```
access-list cached ACL log flows: total 0, denied 0 (deny-flow-max 4096)
            alert-interval 300
access-list outside_in; 2 elements; name hash: 0xc5896c24
access-list outside_in line 1 extended permit tcp any host 172.16.16.16 eq ssh (hitcnt=13) 0xd3b8e9a3 
access-list outside_in line 2 extended permit icmp any host 172.16.16.16 echo 0 (hitcnt=0) 0x7828b608 
access-list inside_in; 1 elements; name hash: 0xd3a8690b
access-list inside_in line 1 extended deny ip any4 host 150.150.150.150 (hitcnt=1) 0x6643b58b 
```
- re-generate completely new access-policies based on traffic. This approach been rejected, due to migration complexities. 

## Usage
To make an analysis 3 files required
```
excessive-acl [flags]

Flags:
-r <file> - output of show running-config
-s <file> - syslog with messages %ASA-6-302013, %ASA-6-302020, %ASA-4-106023
-i <file> - output of show route. It is used to identify interface by IP-address
```

In case of syslog file is bigger than 1GB, you may want to increase number of go-routines used for analysis. 
```
-g <num> - number of go-routines
```
My file was 544MB (3.6 Million lines) 
- single go-routine analyzed the file in 80 seconds (CPU utilization increased by 10%)
- 10 go-routines analyzed the file in 9.8 seconds  (CPU utilization jumped up to 100%)

## File formats
Nothing special about `show running-config` or `show route`.
Syslog file: each line should start with **%ASA**, some firewalls add timestamp in front of message , it should be stripped off. Here is an example of "how to" in bash:
```
more syslog.pre | awk -F% '{ print "%"$2 }' > syslog
```

## Output
Find `--- Analysis` tag and look inside:
It creates tree-like output with `<TAB>` as identation.
```
ACL: <ACL name>
    ACE: <ACL entry from the config>
        ACE compiled: capacity + compiled entry
        # of flows: <number>, capacity: <flows capacity>, utilization(%): <utilization>
            <list of flows>
```

The most interesting metrics are capacity and utilization. 

### ACE capacity
Quantity of entites opened by this entry. 

Examples:

*IP-flows*

permit ip host 1.1.1.1 2.2.2.0 255.255.255.0<br>
Capacity 256 (0x100) =  single host * 256 hosts

permit ip host 1.1.1.1 host 2.2.2.2<br>
Capacity 1 =  single host * single host

*TCP-flows*

permit tcp host 1.1.1.1 host 2.2.2.2<br>
Capacity 256 (0x100) = single host * single host * 256 tcp ports
> Comment: If ports are ommited in source address, it is not taken into consideration, due to efemeral ports usually not restricted in ACL-s

permit tcp host 1.1.1.1 host 2.2.2.2 range 22 23<br>
Capacity 2 = single host * single host * 2 tcp ports

permit tcp host 1.1.1.1 2.2.2.0 255.255.255.0 range 22 23<br>
Capacity 512 (0x200) = single host * 256 hosts * 2 tcp ports

permit tcp any 2.2.2.0 255.255.255.0 range 22 23<br>
Capacity 512 (0x200) = single host * 256 hosts * 2 tcp ports
> Comment: any-keyword have capacity 1 to keep numbers low. "any" used in ACL as a placeholder that does't require optimization. For exapmle: above example allow SSH from the internet to specific subnet and optimization on src IPs not needed. 

*ICMP-flows*

permit icmp host 1.1.1.1 host 2.2.2.2<br>
Capacity 65536 (0x10000) = single host * single host * 256 ICMP types * 256 ICMP codes

permit icmp host 1.1.1.1 host 2.2.2.2 8<br>
Capacity 256 (0x100) = single host * single host * 1 ICMP types * 256 ICMP codes

permit icmp host 1.1.1.1 host 2.2.2.2 8 0<br>
Capacity 1 = single host * single host * 1 ICMP types * 1 ICMP codes


### Flows capacity
Every single flow have capacity 1. Multiple flows adds up depends on number of unique hosts / ports / icmp types / codes

Flow:<br>
TCP 1.1.1.1:1025 -> 2.2.2.2:22<br>
Capacity 1

Flows:<br>
TCP 1.1.1.1:1025 -> 2.2.2.2:22<br>
TCP 1.1.1.1:1026 -> 2.2.2.2:22<br>
Capacity 2

Flows:<br>
TCP 1.1.1.1:1025 -> 2.2.2.2:22<br>
TCP 1.1.1.2:1026 -> 2.2.2.2:22<br>
Capacity 4 = 2 src hosts * 2 src ports * 1 dst host * 1 dst port



### Utilization
Metric of how well ACE utilizaed against flows matched under this entry.
- If utilization is very low ~0 means ACE capacity much higher than traffic matches this ACL
- If utilization 100%, means ACE matched perfectly with given traffic

> I found numbers above 0.5% (half of a percent) are more or less acceptable in production.
>
> If it is 0.000% then take a closer look at this ACE, or add more traffic data.


## Output example
```
--- Analysis
ACL: inside_in
	ACE: access-list inside_in extended permit tcp 10.10.10.10 255.255.255.255 any eq 22
		ACE compiled: capacity 0x1, 1 tcp 10.10.10.10-10.10.10.10 0.0.0.0-255.255.255.255:22-22
		# of flows: 2, capacity: 0x1, ACE capacity utilization(%): 100.000
			 inside->outside tcp://10.10.10.10:57346 -> 150.150.150.150:22
			 inside->outside tcp://10.10.10.10:57347 -> 151.151.151.151:22
=== Analysis (0 sec)
```
