# Coleganet-Install-Mining-Pool-Software UBUNTU 18.04 - 20.04
Install and Build Mining Pool for Any Cryptocurrency Altcoins and Algorithms on Yiimp (Multi Coins/Algo Mining Pool Software)
----------------

We provide altcoin cryptocurrencies mining pool installation and creation services and you just sit back and let us take care of everything from scratch to finish that includes but not limited to 

- Installation of your choice of cryptocurrency wallets/daemon for mining purpose
- Setting up, configuring, administer and prepare server for yiiimp mining software to enable mining for your choice of coins
- Whether you want a solo, private mining pool for personal mining or a mining pool to share with your friends or public
- You can set any fees of your choice or set zero fees that can always be changed as per your desire
- You can use your own equipment to mine such as CPUs, GPU rigs, ASIC machines or even pool can be made compatiable for **Nicehash** mining if you want to use their hashpower.
- It can be multiple coin and multi algorithms mining pool as more coins can be added at any stage provided those algo/coins are are supported by the software and your pool server.
- We do privide maintence service although not much maintence is needed after pool is setup, if you do not touch any exisitng settings etc.
- Configuration, troubleshooting of servers Linux/Ubuntu and existing pools, such as reject blocks, payouts not working, custom difficulty, vardiff, autoexchange, daemon and any other yiimp pool problems we can fix and make your pool running for smooth mining.
- Optimize and Tweak server and yiimp software for improved performance.
- Any special features or customization also possible at additional cost.

How Does it Work?
----------
You will be required to get a VPS or cloud service like AWS instance etc or a server that can be obtained from several hosts online or if you have your very own server at your premises that can also be used to setup pool. For detailed minimum specifications and operating system that is usually Ubuntu/Linux,
Install script for yiimp on Ubuntu Server 20.04 / 18.04 (use Tpruvot's Yiimp)
USE THIS SCRIPT ON FRESH INSTALL UBUNTU Server 20.04 / 18.04 !
For more strong pool in docker container visit the MAIN branch
## INSTALL

apt upgrade

sudo su''

sudo apt -y install git

git clone -b ubuntu https://github.com/Coleganet/Coleganet-Pool-Install.git

cd Coleganet/Coleganet-Pool-Install

bash install.sh 

‼️ Kudaraidee Install Sourcex :
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




 
