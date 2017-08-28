# ipsetupdate
zsh script for updating ipsets using domain names aswell as IP addresses

This can be useful for blacklisting IP addresses with iptables, e.g. see http://iplists.firehol.org/

Usage: ipsetupdate.sh -n <NAME> [-h] [-p] [-c \"<OPTS>\"] [-a \"<OPTS>\"] [-i \"<ELEM>..\"] [-f \"<FILE>..\"] [-u \"<URL>..\"]  
where: 

 -h              = show this help  
 -l	             = list information about existing ipsets  
 -n <NAME>       = name of ipset to create/add to (if it doesnt yet exist it will be created)  
 -t <TYPE>       = type of ipset, default is \"hash:net\"  
 -p              = append only (dont flush the ipset before adding)  
 -c \"<OPTS>\"   = options for 'ipset create' (see ipset manpage)  
 -a \"<OPTS>\"   = options for 'ipset add' (see ipset manpage)  
 -i \"<ELEM>..\" = list of elements to add to the ipset (IP/MAC addresses, ports, etc - see ipset manpage)  
 -f \"<FILE>..\" = list of files containing elements to add to the ipset (one element per line)  
 -u \"<URL>..\"  = list of URLs to webpages containing elements to add to the ipset (one element per line)  
 
Note: domain names may be used instead of IP addresses in which case a reverse DNS lookup will be performed and  
      elements for each corresponding IP address will be added.  
      For example imap.google.com,tcp:993 would be replaced by: 74.125.71.108,tcp:993 and 74.125.71.109,tcp:993  
      Also lines starting with # or ; in files or webpages will be treated as comments and ignored  
