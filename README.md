# NSE
My nmap NSE scripts
<br>
ipmi-ipmiutil-brute.nse - Performs brute force password auditing against IPMI server with 'ipmiutil' and change default password if 'pwdchange' argument >= 5 symbols with 'ipmitool'.<br>
<br>
Install
apt-get install ipmiutil ipmitool<br>
cd /usr/share/nmap/scripts (cd nmap scripts folder)<br>
wget https://github.com/mowerty/NSE/raw/master/ipmi-ipmiutil-brute.nse<br>
nmap --script-updatedb<br>
