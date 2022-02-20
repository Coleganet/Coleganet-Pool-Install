# Coleganet-Install-Mining-Pool-Software UBUNTU 20.04
Install and Build Mining Pool for Any Cryptocurrency Altcoins and Algorithms on Yiimp (Multi Coins/Algo Mining Pool Software)
----------------
After 4 covids and being very weak and always in bed I  rebuilt this script to install yiimp pool in a clean docker container with UBUNTU 20.04
I take many hours to do because the script has many different configurations and I am just using Sansumg 8 Mobile Phone :(
The script work with Proxysql and Mariadb to try to be protected by attacks.

I think the script is bug-free but anyone is welcome to help in the development. If you are using a Stalone Ubuntu Server please use the branch in this repository with the tag Ubuntu. Perhaps this script also works but use Supervisor and not Systemctl for start and... any services.

UFW and Fail2ban are not intended to be include in the script because the docker is protected or by your server holding the docker container or just wait the next updates :)

# DEVELOPMENT:
We need people to upgrade  Yiimp skeleton pool to the version II or perhaps rebuild with Lavarel. If you want to help push a new tag again this repository with your sources

DOcker setup and new ideas are always welcome


# FEATURES

- Installation of your choice of cryptocurrency wallets/daemon for mining purpose
- Setting up, configuring, administer and prepare server for yiiimp mining software to enable mining for your choice of coins
- Whether you want a solo, private mining pool for personal mining or a mining pool to share with your friends or public
- You can set any fees of your choice or set zero fees that can always be changed as per your desire
- You can use your own equipment to mine such as CPUs, GPU rigs, ASIC machines or even pool can be made compatiable for **Nicehash** mining if you want to use their hashpower.
- It can be multiple coin and multi algorithms mining pool as more coins can be added at any stage provided those algo/coins are are supported by the software and your pool server.
- We not provide maintence service although not much maintence is needed after pool is setup, if you do not touch any exisitng settings etc.
- Configuration, troubleshooting of servers Linux/Ubuntu and existing pools, such as reject blocks, payouts not working, custom difficulty, vardiff, autoexchange, daemon and any other yiimp pool problems we can fix and make your pool running for smooth mining.
- Optimize and Tweak server and yiimp software for improved performance.
- If you need Any special features or customization also possible at additional cost.

How Does it Work?
----------
You will be required to get a DOCKER CONTAINERS instance etc or a server that can be obtained from several hosts online or if you have your very own server at your premises that can also be used to setup pool. For detailed minimum specifications and operating system that is usually Ubuntu/Linux,
USE THIS SCRIPT ON FRESH INSTALL UBUNTU Server 20.04 !

Connect on your DOCKER =>
Coleganet use a new theme and add mysql management inside the administration 

sudo su

cd $HOME

git clone https://github.com/Coleganet/Coleganet-Pool-Install.git

cd Coleganet-Pool-Install

bash install.sh

At the end, you MUST REBOOT to finalize installation...
Finish !

# Docker
if you pull the two coleganet containers from docker.io
remember to execute the command first start that will setup
new passwords for the applications. You only will need to copy 
and save the new passwords and change accordingly you Docker-compose.yml
for all the users match youe new security passwords,

is a good idea them to save your docker with a new tag






# Common Errors
You need to setup A dns records for your domain 48 hours before you setup this script or install the already build containers from Docker.io

In case you have a certificate error use dothis :

rm /etc/nginx/sites-enabled/mydomain.com.conf

sudo certbot --nginx

them write your domain and certboot will generate a new certificate if you get a new error you have a problem with your dns.
After that execute: 
ln -s /etc/nginx/sites-available/subdomain.mydomain.com.conf /etc/nginx/sites-enabled

Them restart the server

# ProxySQL Internals
ProxySQL, when started, immediately spawns a new process - the parent process works as an angel process and restarts ProxySQL
within milliseconds of a crash. If you are familiar with MySQL, this is fairly similar to mysqld_safe. By default, ProxySQL 
needs two ports: 6033, on which it listens for traffic and 6032, which works as a gateway for managing ProxySQL. The command 
line admin interface can be accessed by a MySQL client - the majority of the configuration is done using SQL. Even though the 
underlying database that ProxySQL uses to store its configuration is SQLite, an effort was put into making the experience as 
close to MySQL as possible. You can use some of the MySQL syntax to check the ProxySQL configuration (SHOW GLOBAL VARIABLES) 
or set a new one (SET GLOBAL variable_name = value). The backend configuration is stored in tables - all changes are made through
 SQL: INSERT, UPDATE, DELETE
For access directly to your database we not use anymore phpmyadmin for security reasons 
You can simple do us root

service webmin start
Them you access directly to your database 
Go or visit in any browser like Firefox to the url

https://mypublicDockerIp:15000 and setup your new mysql password you save
them you can see directly the Mariadb container and database.
Remember always stop Webmin after you finished,





Go http://xxx.xxx.xxx.xxx or https://xxx.xxx.xxx.xxx (if you have chosen LetsEncrypt SSL). Enjoy !
Go http://xxx.xxx.xxx.xxx/AdminPanel or https://xxx.xxx.xxx.xxx/AdminPanel to access Panel Admin
If you are issue after installation (nginx,mariadb... not found), use this script : bash install-debug.sh (watch the log during installation)

‼️ Kudaraidee Install Sources :
Instead Tpruvot's Yiimp, you can use the Kudaraidee's Repo Yiimp : git clone -b Kudaraidee https://github.com/Kudaraidee/yiimp.git
It's an updated Yiimp, with more algo, some fix....
‼️ YOU MUST UPDATE THE FOLLOWING FILES :
/var/web/serverconfig.php : update this file to include your public ip (line = YAAMP_ADMIN_IP) to access the admin panel (Put your PERSONNAL IP, NOT IP of your VPS). update with public keys from exchanges. update with other information specific to your server..
/etc/yiimp/keys.php : update with secrect keys from the exchanges (not mandatory)
If you want change 'AdminPanel' to access Panel Admin : Edit this file "/var/web/yaamp/modules/site/SiteController.php" and Line 11 => change 'AdminPanel'
‼️ IMPORTANT :
The configuration of yiimp and coin require a minimum of knowledge in linux
Your mysql information (login/Password) is saved in ~/.my.cnf
This script has an interactive beginning and will ask for the following information :
Server Name (no http:// or www !!!!! Example : crypto.com OR pool.crypto.com OR 80.41.52.63)
Are you using a subdomain (mypoolx11.crypto.com)
Enter support email
Set stratum to AutoExchange
Your Public IP for admin access (Put your PERSONNAL IP, NOT IP of your VPS)
Install Fail2ban
Install UFW and configure ports
Install LetsEncrypt SSL
This install script will get you 95% ready to go with yiimp. There are a few things you need to do after the main install is finished.

While I did add some server security to the script, it is every server owners responsibility to fully secure their own servers. After the installation you will still need to customize your serverconfig.php file to your liking, add your API keys, and build/add your coins to the control panel.

There will be several wallets already in yiimp. These have nothing to do with the installation script and are from the database import from the yiimp github.


#### YIIMP SOFTWARE SUPPORTED ALGORITHMS FOR CRYPTOCURRENCY / COINS MINING

#### YIIMP SOFTWARE SUPPORTED ALGORITHMS FOR CRYPTOCURRENCY / COINS MINING

  Algos | Algos  | Algos | Algos | Algos  | Algos
------------- | ------------- | ------------- | ------------- | ------------- | -------------
a5a  | fresh | lyra2v2 | qubit | timetravel | x14
argon2  | bastion | bitcore | blake | blake2s | blakecoin
c11  | deep | dmd-gr | lyra2z330 | Lyra2REv3 | geek
dedal  | hive | hmq1725 | hsr | jha | keccak
keccakc  | lbry | luffa | lyra2 | Argon | rainforest
astralhash  | SHA256Q | lyra2z | m7m | myr-gr | neoscrypt
nist5  | penta | phi | phi2 | polytimos | quark
vitalium  | x22i | jeonghash | scrypt | scryptn | sha
sha256d  | sha256 | sha256t | sib | skein | skunk
allium  | lbk3 | powerhash | tribus | vanilla | veltor
velvet  | whirlpool | x11 | x11evo | x12 | x13
aergo  | exosis | X20R | x15 | x16r | x16s
x17  | xevan | yescrypt | yescryptR32 | yescryptR16 | groestl
sonoa  | X21S | bcd (x13) | blake2b | YescryptR8 | x21s
x16rt  | Lyra2vc0ban | Trihash | Argon2m | Binarium-V1 | x18
keccakd  | lyra2zz (LAPO/LAX) |  x16rv2 | Kawpow | - | -


