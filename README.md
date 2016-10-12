# zabbix-burp

Monitor burp with zabbix

How to install
==============

Binary
------
- copy the binary to `/usr/local/bin`

```bash
# cp burp_latest_backup.py /usr/local/bin
```

Sudoers
-------
- Allow the zabbix user in sudoers.d directory:

```bash
# cat << __EOF > /etc/sudoers.d/zabbix_burp
User_Alias  ZABBIX_BURP_USERS = zabbix
Host_Alias  ZABBIX_BURP_HOSTS = ALL
Runas_Alias ZABBIX_BURP_RUNAS = root
Cmnd_Alias  ZABBIX_BURP_CMNDS = /usr/local/bin/burp_latest_backup.py


ZABBIX_BURP_USERS ZABBIX_BURP_HOSTS = (ZABBIX_BURP_RUNAS) NOPASSWD: ZABBIX_BURP_CMNDS
__EOF
```

Zabbix
------

- import the template (`zbx_burp_template.xml`) into the zabbix GUI
- Add the UserParameter in the zabbix config directory
