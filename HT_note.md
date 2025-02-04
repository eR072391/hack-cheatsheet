## 21 FTP
```
Protocol_Name: FTP    #Protocol Abbreviation if there is one.
Port_Number:  21     #Comma separated if there is more than one.
Protocol_Description: File Transfer Protocol          #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for FTP
  Note: |
    Anonymous Login
    -bi     <<< so that your put is done via binary

    wget --mirror 'ftp://ftp_user:UTDRSCH53c"$6hys@10.10.10.59'
    ^^to download all dirs and files

    wget --no-passive-ftp --mirror 'ftp://anonymous:anonymous@10.10.10.98'
    if PASV transfer is disabled

    https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ftp/index.html

Entry_2:
  Name: Banner Grab
  Description: Grab FTP Banner via telnet
  Command: telnet -n {IP} 21

Entry_3:
  Name: Cert Grab
  Description: Grab FTP Certificate if existing
  Command: openssl s_client -connect {IP}:21 -starttls ftp

Entry_4:
  Name: nmap ftp
  Description: Anon login and bounce FTP checks are performed
  Command: nmap --script ftp-* -p 21 {IP}

Entry_5:
  Name: Browser Connection
  Description: Connect with Browser
  Note: ftp://anonymous:anonymous@{IP}

Entry_6:
  Name: Hydra Brute Force
  Description: Need Username
  Command: hydra -t 1 -l {Username} -P {Big_Passwordlist} -vV {IP} ftp

Entry_7:
  Name: consolesless mfs enumeration ftp
  Description: FTP enumeration without the need to run msfconsole
  Note: sourced from https://github.com/carlospolop/legion
  Command: msfconsole -q -x 'use auxiliary/scanner/ftp/anonymous; set RHOSTS {IP}; set RPORT 21; run; exit' && msfconsole -q -x 'use auxiliary/scanner/ftp/ftp_version; set RHOSTS {IP}; set RPORT 21; run; exit' && msfconsole -q -x 'use auxiliary/scanner/ftp/bison_ftp_traversal; set RHOSTS {IP}; set RPORT 21; run; exit' && msfconsole -q -x 'use auxiliary/scanner/ftp/colorado_ftp_traversal; set RHOSTS {IP}; set RPORT 21; run; exit' &&  msfconsole -q -x 'use auxiliary/scanner/ftp/titanftp_xcrc_traversal; set RHOSTS {IP}; set RPORT 21; run; exit'
```

## 22 SSH/SFTP
```
Protocol_Name: SSH
Port_Number: 22
Protocol_Description: Secure Shell Hardening

Entry_1:
  Name: Hydra Brute Force
  Description: Need Username
  Command: hydra -v -V -u -l {Username} -P {Big_Passwordlist} -t 1 {IP} ssh

Entry_2:
  Name: consolesless mfs enumeration
  Description: SSH enumeration without the need to run msfconsole
  Note: sourced from https://github.com/carlospolop/legion
  Command: msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_version; set RHOSTS {IP}; set RPORT 22; run; exit' && msfconsole -q -x 'use scanner/ssh/ssh_enumusers; set RHOSTS {IP}; set RPORT 22; run; exit' && msfconsole -q -x 'use auxiliary/scanner/ssh/juniper_backdoor; set RHOSTS {IP}; set RPORT 22; run; exit'
```

## 23 Telnet
```
Protocol_Name: Telnet    #Protocol Abbreviation if there is one.
Port_Number:  23     #Comma separated if there is more than one.
Protocol_Description: Telnet          #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for t=Telnet
  Note: |
    wireshark to hear creds being passed
    tcp.port == 23 and ip.addr != myip

    https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-telnet.html

Entry_2:
  Name: Banner Grab
  Description: Grab Telnet Banner
  Command: nc -vn {IP} 23

Entry_3:
  Name: Nmap with scripts
  Description: Run nmap scripts for telnet
  Command: nmap -n -sV -Pn --script "*telnet*" -p 23 {IP}

Entry_4:
  Name: consoleless mfs enumeration
  Description: Telnet enumeration without the need to run msfconsole
  Note: sourced from https://github.com/carlospolop/legion
  Command: msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_version; set RHOSTS {IP}; set RPORT 23; run; exit' && msfconsole -q -x 'use auxiliary/scanner/telnet/brocade_enable_login; set RHOSTS {IP}; set RPORT 23; run; exit' && msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_encrypt_overflow; set RHOSTS {IP}; set RPORT 23; run; exit' && msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_ruggedcom; set RHOSTS {IP}; set RPORT 23; run; exit'
```

## 25,465,587 SMTP/s
```
Protocol_Name: SMTP    #Protocol Abbreviation if there is one.
Port_Number:  25,465,587     #Comma separated if there is more than one.
Protocol_Description: Simple Mail Transfer Protocol          #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for SMTP
  Note: |
    SMTP (Simple Mail Transfer Protocol) is a TCP/IP protocol used in sending and receiving e-mail. However, since it is limited in its ability to queue messages at the receiving end, it is usually used with one of two other protocols, POP3 or IMAP, that let the user save messages in a server mailbox and download them periodically from the server.

    https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smtp/index.html

Entry_2:
  Name: Banner Grab
  Description: Grab SMTP Banner
  Command: nc -vn {IP} 25

Entry_3:
  Name: SMTP Vuln Scan
  Description: SMTP Vuln Scan With Nmap
  Command: nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 {IP}

Entry_4:
  Name: SMTP User Enum
  Description: Enumerate uses with smtp-user-enum
  Command: smtp-user-enum -M VRFY -U {Big_Userlist} -t {IP}

Entry_5:
  Name: SMTPS Connect
  Description: Attempt to connect to SMTPS two different ways
  Command: openssl s_client -crlf -connect {IP}:465 &&&& openssl s_client -starttls smtp -crlf -connect {IP}:587

Entry_6:
  Name: Find MX Servers
  Description: Find MX servers of an organization
  Command: dig +short mx {Domain_Name}

Entry_7:
  Name: Hydra Brute Force
  Description: Need Nothing
  Command: hydra -P {Big_Passwordlist} {IP} smtp -V

Entry_8:
  Name: consolesless mfs enumeration
  Description: SMTP enumeration without the need to run msfconsole
  Note: sourced from https://github.com/carlospolop/legion
  Command: msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_version; set RHOSTS {IP}; set RPORT 25; run; exit' && msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_ntlm_domain; set RHOSTS {IP}; set RPORT 25; run; exit' && msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_relay; set RHOSTS {IP}; set RPORT 25; run; exit'
```

## 43 WHOIS
```
Protocol_Name: WHOIS    #Protocol Abbreviation if there is one.
Port_Number:  43     #Comma separated if there is more than one.
Protocol_Description: WHOIS         #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for WHOIS
  Note: |
    The WHOIS protocol serves as a standard method for inquiring about the registrants or holders of various Internet resources through specific databases. These resources encompass domain names, blocks of IP addresses, and autonomous systems, among others. Beyond these, the protocol finds application in accessing a broader spectrum of information.


    https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smtp/index.html

Entry_2:
  Name: Banner Grab
  Description: Grab WHOIS Banner
  Command: whois -h {IP} -p 43 {Domain_Name} && echo {Domain_Name} | nc -vn {IP} 43
```

## 53 DNS
```
Protocol_Name: DNS    #Protocol Abbreviation if there is one.
Port_Number:  53     #Comma separated if there is more than one.
Protocol_Description: Domain Name Service        #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for DNS
  Note: |
    #These are the commands I run every time I see an open DNS port

    dnsrecon -r 127.0.0.0/24 -n {IP} -d {Domain_Name}
    dnsrecon -r 127.0.1.0/24 -n {IP} -d {Domain_Name}
    dnsrecon -r {Network}{CIDR} -n {IP} -d {Domain_Name}
    dig axfr @{IP}
    dig axfr {Domain_Name} @{IP}
    nslookup
        SERVER {IP}
        127.0.0.1
        {IP}
        Domain_Name
        exit

    https://book.hacktricks.wiki/en/todo/pentesting-dns.html

Entry_2:
  Name: Banner Grab
  Description: Grab DNS Banner
  Command: dig version.bind CHAOS TXT @DNS

Entry_3:
  Name: Nmap Vuln Scan
  Description: Scan for Vulnerabilities with Nmap
  Command: nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" {IP}

Entry_4:
  Name: Zone Transfer
  Description: Three attempts at forcing a zone transfer
  Command: dig axfr @{IP} && dix axfr @{IP} {Domain_Name} && fierce --dns-servers {IP} --domain {Domain_Name}


Entry_5:
  Name: Active Directory
  Description: Eunuerate a DC via DNS
  Command: dig -t _gc._{Domain_Name} && dig -t _ldap._{Domain_Name} && dig -t _kerberos._{Domain_Name} && dig -t _kpasswd._{Domain_Name} && nmap --script dns-srv-enum --script-args "dns-srv-enum.domain={Domain_Name}"

Entry_6:
  Name: consolesless mfs enumeration
  Description: DNS enumeration without the need to run msfconsole
  Note: sourced from https://github.com/carlospolop/legion
  Command: msfconsole -q -x 'use auxiliary/scanner/dns/dns_amp; set RHOSTS {IP}; set RPORT 53; run; exit' && msfconsole -q -x 'use auxiliary/gather/enum_dns; set RHOSTS {IP}; set RPORT 53; run; exit'
```

## 80,443 Web
```
Protocol_Name: Web    #Protocol Abbreviation if there is one.
Port_Number:  80,443     #Comma separated if there is more than one.
Protocol_Description: Web         #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for Web
  Note: |
    https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html

Entry_2:
  Name: Quick Web Scan
  Description: Nikto and GoBuster
  Command: nikto -host {Web_Proto}://{IP}:{Web_Port} &&&& gobuster dir -w {Small_Dirlist} -u {Web_Proto}://{IP}:{Web_Port} && gobuster dir -w {Big_Dirlist} -u {Web_Proto}://{IP}:{Web_Port}

Entry_3:
  Name: Nikto
  Description: Basic Site Info via Nikto
  Command: nikto -host {Web_Proto}://{IP}:{Web_Port}

Entry_4:
  Name: WhatWeb
  Description: General purpose auto scanner
  Command: whatweb -a 4 {IP}

Entry_5:
  Name: Directory Brute Force Non-Recursive
  Description:  Non-Recursive Directory Brute Force
  Command: gobuster dir -w {Big_Dirlist} -u {Web_Proto}://{IP}:{Web_Port}

Entry_6:
  Name: Directory Brute Force Recursive
  Description: Recursive Directory Brute Force
  Command: python3 {Tool_Dir}dirsearch/dirsearch.py -w {Small_Dirlist} -e php,exe,sh,py,html,pl -f -t 20 -u {Web_Proto}://{IP}:{Web_Port} -r 10

Entry_7:
  Name: Directory Brute Force CGI
  Description: Common Gateway Interface Brute Force
  Command: gobuster dir -u {Web_Proto}://{IP}:{Web_Port}/ -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -s 200

Entry_8:
  Name: Nmap Web Vuln Scan
  Description: Tailored Nmap Scan for web Vulnerabilities
  Command: nmap -vv --reason -Pn -sV -p {Web_Port} --script=`banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)` {IP}

Entry_9:
  Name: Drupal
  Description: Drupal Enumeration Notes
  Note: |
    git clone https://github.com/immunIT/drupwn.git for low hanging fruit and git clone https://github.com/droope/droopescan.git for deeper enumeration

Entry_10:
  Name: WordPress
  Description: WordPress Enumeration with WPScan
  Command: |
    ?What is the location of the wp-login.php? Example: /Yeet/cannon/wp-login.php
    wpscan --url {Web_Proto}://{IP}{1} --enumerate ap,at,cb,dbe && wpscan --url {Web_Proto}://{IP}{1} --enumerate u,tt,t,vp --passwords {Big_Passwordlist} -e

Entry_11:
  Name: WordPress Hydra Brute Force
  Description: Need User (admin is default)
  Command: hydra -l admin -P {Big_Passwordlist} {IP} -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'

Entry_12:
  Name: Ffuf Vhost
  Description: Simple Scan with Ffuf for discovering additional vhosts
  Command: ffuf -w {Subdomain_List}:FUZZ -u {Web_Proto}://{Domain_Name} -H "Host:FUZZ.{Domain_Name}" -c -mc all {Ffuf_Filters}
```

## 88 Kerberos
```
Protocol_Name: Kerberos    #Protocol Abbreviation if there is one.
Port_Number:  88   #Comma separated if there is more than one.
Protocol_Description: AD Domain Authentication         #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for Kerberos
  Note: |
    Kerberos operates on a principle where it authenticates users without directly managing their access to resources. This is an important distinction because it underlines the protocol's role in security frameworks.
    In environments like **Active Directory**, Kerberos is instrumental in establishing the identity of users by validating their secret passwords. This process ensures that each user's identity is confirmed before they interact with network resources. However, Kerberos does not extend its functionality to evaluate or enforce the permissions a user has over specific resources or services. Instead, it provides a secure way of authenticating users, which is a critical first step in the security process.

    https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-kerberos-88/index.html

Entry_2:
  Name: Pre-Creds
  Description: Brute Force to get Usernames
  Command: nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm="{Domain_Name}",userdb={Big_Userlist} {IP}

Entry_3:
  Name: With Usernames
  Description: Brute Force with Usernames and Passwords
  Note: consider git clone https://github.com/ropnop/kerbrute.git ./kerbrute -h

Entry_4:
  Name: With Creds
  Description: Attempt to get a list of user service principal names
  Command: GetUserSPNs.py -request -dc-ip {IP} active.htb/svc_tgs
```

## 110,995 POP
```
Protocol_Name:  POP   #Protocol Abbreviation if there is one.
Port_Number:  110     #Comma separated if there is more than one.
Protocol_Description: Post Office Protocol         #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for POP
  Note: |
    Post Office Protocol (POP) is described as a protocol within the realm of computer networking and the Internet, which is utilized for the extraction and retrieval of email from a remote mail server**, making it accessible on the local device. Positioned within the application layer of the OSI model, this protocol enables users to fetch and receive email. The operation of POP clients typically involves establishing a connection to the mail server, downloading all messages, storing these messages locally on the client system, and subsequently removing them from the server. Although there are three iterations of this protocol, POP3 stands out as the most prevalently employed version.

    https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-pop.html

Entry_2:
  Name: Banner Grab
  Description: Banner Grab 110
  Command: nc -nv {IP} 110

Entry_3:
  Name: Banner Grab 995
  Description: Grab Banner Secure
  Command: openssl s_client -connect {IP}:995 -crlf -quiet

Entry_4:
  Name: Nmap
  Description: Scan for POP info
  Command: nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -p 110 {IP}

Entry_5:
  Name: Hydra Brute Force
  Description: Need User
  Command: hydra -l {Username} -P {Big_Passwordlist} -f {IP} pop3 -V

Entry_6:
  Name: consolesless mfs enumeration
  Description: POP3 enumeration without the need to run msfconsole
  Note: sourced from https://github.com/carlospolop/legion
  Command: msfconsole -q -x 'use auxiliary/scanner/pop3/pop3_version; set RHOSTS {IP}; set RPORT 110; run; exit'
```

## 111 Portmapper
```
Protocol_Name: Portmapper    #Protocol Abbreviation if there is one.
Port_Number:  43     #Comma separated if there is more than one.
Protocol_Description: PM or RPCBind        #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for PortMapper
  Note: |
    Portmapper is a service that is utilized for mapping network service ports to RPC (Remote Procedure Call) program numbers. It acts as a critical component in Unix-based systems, facilitating the exchange of information between these systems. The port associated with Portmapper is frequently scanned by attackers as it can reveal valuable information. This information includes the type of Unix Operating System (OS) running and details about the services that are available on the system. Additionally, Portmapper is commonly used in conjunction with NFS (Network File System), NIS (Network Information Service), and other RPC-based services to manage network services effectively.

    https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-rpcbind.html

Entry_2:
  Name: rpc info
  Description: May give netstat-type info
  Command: whois -h {IP} -p 43 {Domain_Name} && echo {Domain_Name} | nc -vn {IP} 43

Entry_3:
  Name: nmap
  Description: May give netstat-type info
  Command: nmap -sSUC -p 111 {IP}
```

### 113 Ident
```
Protocol_Name: Ident    #Protocol Abbreviation if there is one.
Port_Number:  113     #Comma separated if there is more than one.
Protocol_Description: Identification Protocol         #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for Ident
  Note: |
    The Ident Protocol is used over the Internet to associate a TCP connection with a specific user. Originally designed to aid in network management and security, it operates by allowing a server to query a client on port 113 to request information about the user of a particular TCP connection.

    https://book.hacktricks.wiki/en/network-services-pentesting/113-pentesting-ident.html

Entry_2:
  Name: Enum Users
  Description: Enumerate Users
  Note: apt install ident-user-enum    ident-user-enum {IP} 22 23 139 445 (try all open ports)
```

### 123 NTP
```
Protocol_Name: NTP    #Protocol Abbreviation if there is one.
Port_Number:  123     #Comma separated if there is more than one.
Protocol_Description: Network Time Protocol         #Protocol Abbreviation Spelled out

Entry_1:
  Name: Notes
  Description: Notes for NTP
  Note: |
    The Network Time Protocol (NTP) ensures computers and network devices across variable-latency networks sync their clocks accurately. It's vital for maintaining precise timekeeping in IT operations, security, and logging. NTP's accuracy is essential, but it also poses security risks if not properly managed.

    https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ntp.html

Entry_2:
  Name: Nmap
  Description: Enumerate NTP
  Command: nmap -sU -sV --script "ntp* and (discovery or vuln) and not (dos or brute)" -p 123 {IP}
```

