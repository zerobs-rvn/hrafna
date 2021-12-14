
### Hrafna - Log4j-Scanner for the masses 


Features 

- Scanning-system designed to check your own infra for vulnerable log4j-installations
- start and stop scans ([CTRL-C] is your friend), continue and skip already tested
- use your own DNS-server that listens to Requests from scanned hosts
- unique requests for each host to be scanned 
- easy to correlate which host sends a callback
- reportmode to see which hosts made a callback

### unique requests

- each payload is unique, so you can see which host triggered
  a response or maybe backend-system were connected 

~~~

PAYLOAD: e3a4d77618a0  .  3c028d   .  l4s.scanix.edu
         ^^^              ^^^         ^^^
         host_id          scan_id     your custom nameserver


~~~


![img](img/hrafna.png)


### install

- install packages from requirements.txt
- instructions for the BIND-setup are below 


### config

- l4s.scanix.edu is our example here, change according to your own needs 


- global_config

~~~

global.yaml

base_scan_domain: l4s.scanix.edu
bind_log: /var/log/bind/hrafna.log

~~~

- each scan has a unique config-file in yaml-format

~~~

scan.yaml

name: your_scan_name
mode: default
input_file: hostnames.txt

# 

~~~


- name: give your scan a name (alphanum, spaces will get converted to "_"
- mode:
    - default 8currently the only mode, but more will get added as new
      attackvectors are dropping in, "vmware" is already in testing
- input_file: your file with targets (IPs or hostnames), full urls
  including ports preferred, otherwise only https://target/ is checked

optional:

~~~

# waf_bypass: True | False (tbd)
# headers: headers.txt (tbd) which headers_file to use, must be available in libs/  

~~~



### run


./hrafna scan scan.yaml -> execute/continue a scan

./hrafna report scan.yaml

./hrafna reset scan.yaml


# Setup the scanner

- have your dns-server and your scanner on the same maschine for auto_reports
  (scanner neesd to read the bind-logfile)
  

  

# your bind config

- GOTO DNS-Zonefile


- lcoal named.conf 

~~~

# named.conf.local

...


zone "l4s.scanix.edu." {
        type master;
        file "/etc/bind/l4s.zone";
};

logging {
  channel "querylog" {
    file "/var/log/bind9/hrafna.log";
    print-time yes;
  };
  category queries { querylog; };
};

...

~~~


- bind_zonefile  - change l4s.scanix.edu to your own domain / subdomain

~~~

# /etc/bind/l4s.zone

; l4s.scanix.edu
$TTL 60
l4s.scanix.edu. IN     SOA    a.root-servers.net. technik@zero.bs. (
                                2021121301  ; Serial
                                1H          ; refresh after 3 hours
                                30m          ; retry after 1 hour
                                1H          ; expire after 1 week
                                1D)         ; minimum TTL of 1 day

                                IN      NS      l4s.scanix.edu.


l4s.scanix.edu.                  IN A            1.2.3.4
l4s.scanix.edu.                  IN AAAA         2a01:4f8::::

*                               IN A            1.2.3.4           
*                               IN AAAA         2a01:4f8:::::

~~~




