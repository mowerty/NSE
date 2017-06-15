# NSE
My nmap NSE scripts

ipmi-ipmiutil-brute.nse - Performs brute force password auditing against IPMI server with 'ipmiutil' and change default password if 'pwdchange' argument >= 5 symbols with 'ipmitool'.

Install
apt-get install ipmiutil ipmitool
cd /usr/share/nmap/scripts (cd nmap scripts folder)
wget https://github.com/mowerty/NSE/raw/master/ipmi-ipmiutil-brute.nse
nmap --script-updatedb
