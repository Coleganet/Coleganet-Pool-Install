#!/bin/bash
###############################################################################
# Author:   coleganet
#
# Web:      www.coleganet.com
#
# Program:
#   Install Coleganet Pool on Ubuntu 18.04 runnin
#        Nginx, MariaDB, and php7.x
# BTC Donation:1K5qZcCT8ZGzLfbR75GWJNXo3MViaZrvq7
#
################################################################################
output() {
   printf "\E[0;33;40m"
   echo $1
   printf "\E[0m"
}

displayErr() {
   echo
   echo $1;
   echo
   exit 1;
}
   output " For Debug the script in case of errors execute  bash -x install.sh"
   output " Do not run the pool as root : create a new user without ssh access to avoid security issues : "

   sudo adduser --disabled-password --disabled-login pool
   output " To login with this user :sudo su - pool"

    output " "
    output "Make sure you double check before hitting enter! Only one shot at these!"
    outoput " "
    read -e -p "Enter time zone (e.g. Spain/Madrid) : " TIME
    read -e -p "Server name (no http:// or www. just example.com) : " server_name
    read -e -p "Are you using a subdomain (pool.example.com?) [y/N] : " sub_domain
    read -e -p "Enter support email (e.g. admin@example.com) : " EMAIL
    read -e -p "Set stratum to AutoExchange? i.e. mine any coinf with BTC address? [y/N] : " BTC
    read -e -p "Please enter a new location for /site/adminRights this is to customize the admin entrance url (e.g. myAdminpanel) : " admin_panel
    read -e -p "Enter your Public IP for admin access (http://www.whatsmyip.org/) : " Public
    read -e -p "Install LetsEncrypt SSL? IMPORTANT! You MUST have your domain name pointed to this server prior to running the script!! [Y/n]: " ssl_install

    output " "
    output "Updating system and installing required packages."
    output " "
    sleep 3


    # update package and upgrade Ubuntu
    sudo apt-get -y update 
    sudo apt-get -y autoremove

    output "Checking and Updating system and installing basic packages."
    curl -LsS https://r.mariadb.com/downloads/mariadb_repo_setup | sudo bash
    sudo apt remove --purge mariadb-server mariadb-client mysql-server mysql-client -y
    sudo apt install  mariadb-server mariadb-client
    sudo apt install --assume-yes gcc shc
    output " "
    output "Switching to Aptitude"
    output " "
    sleep 3
    sudo apt-get -y install aptitude
    output " "
    output "Installing Nginx server."
    output " "
    sleep 2
    output "If you get an error about add-apt-repository not existing, you will want to install python-software-properties."
    add-apt-repository ppa:nginx/stable
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C300EE8C
    apt update
    apt install nginx
    output "Checking Nginx for start inside Docker container"
    #sudo -- bash -c "echo daemon off; > /etc/nginx/nginx.conf"
    openssl dhparam -out dhparam.pem 4096
    mv dhparam.pem /etc/ssl/certs
    sudo aptitude -y install nginx
    sudo rm /etc/nginx/sites-enabled/default
    sudo service nginx start
    sudo service cron start
    #Making Nginx a bit hard
    echo 'map $http_user_agent $blockedagent {
default         0;
~*malicious     1;
~*bot           1;
~*backdoor      1;
~*crawler       1;
~*bandit        1;
}
' | sudo -E tee /etc/nginx/blockuseragents.rules >/dev/null 2>&1

    cp -r $HOME/Coleganet-Pool-Install/nginx.conf  /etc/nginx

    output " "
    output "Installing Mariadb Server."
    output " "
    sleep 3


    # create random password
    rootpasswd=$(openssl rand -base64 12)
    export DEBIAN_FRONTEND="noninteractive"
    sudo aptitude -y install mariadb-server

    output " "
    output "Installing php7.3 and other needed files please not upgrade PHP  "
    output " "
    sleep 3
    apt-get install software-properties-common
    sudo add-apt-repository -y ppa:ondrej/php
    sudo apt-get update
    #update-alternatives --set php /usr/bin/php7.3
    sudo aptitude -y install php7.3-fpm
    sudo aptitude -y install php7.3-opcache php7.3-fpm php7.3 php7.3-common php7.3-gd php7.3-mysql php7.3-imap php7.3-cli php7.3-cgi php-pear php-auth php7.3-mcrypt mcrypt imagemagick libruby php7.3-curl php7.3-intl php7.3-pspell php7.3-recode php7.3-sqlite3 php7.3-tidy php7.3-xmlrpc php7.3-xsl memcached php-memcache php-imagick php-gettext php7.3-zip php7.3-mbstring php7.3-dev php7.3-dev
    sudo apt-get -y install php-memcache
    sudo apt-get -y install memcached
    sudo apt-get -y install libmcrypt-dev
    sudo phpenmod mcrypt
    sudo pecl channel-update pecl.php.net
    sudo pecl install mcrypt-1.0.3
    sudo apt-get install php7.3-dev
#sudo bash -c "echo extension=/usr/lib/php/20170718/mcrypt.so > /etc/php/7.3/cli/conf.d/mcrypt.ini"
#sudo bash -c "echo extension=/usr/lib/php/20170718/mcrypt.so > /etc/php/7.3/fpm/conf.d/mcrypt.ini"
php -i | grep "mcrypt"

sudo -- bash -c 'echo "mcrypt.so" >>/etc/php/7.3/cli/php.ini'
sudo -- bash -c 'echo "mcrypt.so" >>/etc/php/7.3/fpm/php.ini'
    sudo phpenmod mbstring
    sudo aptitude -y install libgmp3-dev
    sudo aptitude -y install libmysqlclient-dev
    sudo aptitude -y install libcurl4-gnutls-dev
    sudo aptitude -y install libkrb5-dev
    sudo aptitude -y install libldap2-dev
    sudo aptitude -y install libidn11-dev
    sudo aptitude -y install gnutls-dev
    sudo aptitude -y install librtmp-dev
    sudo aptitude -y install sendmail
    sudo aptitude -y install mutt
    sudo aptitude -y install git screen
    sudo aptitude -y install pwgen -y
    sudo apt install gnupg2 pass

    #Installing Package to compile crypto currency
    output " "
    output "Installing Package to compile crypto currency"
    output " "
    sleep 3

    sudo aptitude -y install software-properties-common build-essential
    sudo aptitude -y install libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils git cmake zlib1g-dev libz-dev libseccomp-dev libcap-dev libminiupnpc-dev
  l sudo apt-get install libboost-all-dev
    sudo aptitude -y install libminiupnpc10 libzmq5
    sudo aptitude -y install libcanberra-gtk-module libqrencode-dev libzmq3-dev
    sudo aptitude -y install libqt5gui5 libqt5core5a libqt5webkit5-dev libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler
apt install python3-bitcoinlib
sudo add-apt-repository -y ppa:bitcoin/bitcoin
    sudo apt-get -y update
    sudo apt-get install -y libdb5.3-dev libdb5.3++-dev libdb5.3 libdb5.3++
apt install git-core build-essential libssl-dev libboost-all-dev libdb5.3-dev libdb5.3++-dev libgtk2.0-dev
    #Generating Random Passwords
    password=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1`
    password2=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1`
    AUTOGENERATED_PASS=`pwgen -c -1 20`
    output " Installing Coleganet Pool"
    output " "
    output "Grabbing Coleganet from Github, building files and setting file structure."
    output " "
    sleep 3
    #Generating Random Password for stratum
    blckntifypass=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1`
    cd ~
   sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-key C99B11DEB97541F0
   sudo apt-add-repository https://cli.github.com/packages
   sudo apt update
   sudo apt install git
   sudo apt install gh
   cd $HOME
   git clone https://github.com/Kudaraidee/yiimp.git
   cd $HOME/yiimp
   cp screen_Stratum.sh /etc
    cd $HOME/yiimp/blocknotify
    sudo sed -i 's/tu8tu5/'$blckntifypass'/' blocknotify.cpp
    sudo make
    output " Installing Stratum with New Installer"
    output " If your default compiler is gcc 8.3.0 (Debian 8.3.0-6) you possible will get crash of app after share received "
    sleep 5
    sudo apt-get install -y libbrotli-dev libssh-dev libbrotli-dev libssh-dev
   #cd /root/stratum/iniparser
     cd $HOME/yiimp/iniparser/stratum
    output " Installing any libs we can need for Coleganet Pool"
    apt-get install libmysqlclient-dev
    apt install libnghttp2-dev librtmp-dev libssh2-1 libssh2-1-dev libldap2-dev libidn11-dev libpsl-dev
    apt install libkrb5-d
    sudo apt install libiniparser-dev
    sudo apt‐get install python3‐zmq
    sudo apt‐get install python3‐tornado
    sudo apt‐get install python3‐netifaces
    sudo apt‐get install python3‐setuptools
    sudo apt‐get install python3‐pyqt4
    sudo apt‐get install python3‐ws4py
    output " Ready to make Stratum Pool"
    make -C iniparser/ -j$(nproc)
    make -C algos/ -j$(nproc)
    make -C sha3 -j$(nproc)
    #sudo make
    cd $HOME/yiimp/stratum
    if [[ ("$BTC" == "y" || "$BTC" == "Y") ]]; then
    sudo sed -i 's/CFLAGS += -DNO_EXCHANGE/#CFLAGS += -DNO_EXCHANGE/' $HOME/stratum/Makefile
    # sudo make
    make -f Makefile -j$(nproc)
    fi
    # sudo make
    make -f Makefile -j$(nproc)
    make install
    cd $HOME
    sudo sed -i 's/MasterNode/'$admin_panel'/' $HOME/yiimp/web/yaamp/modules/site/SiteController.php
    sudo cp -r $HOME/yiimp/web /var/
    sudo mkdir -p /var/stratum
    cd $HOME/yiimp/stratum
    sudo cp -a config.sample/. /var/stratum/config
    sudo cp -r stratum /var/stratum
    sudo cp -r run.sh /var/stratum
    cd /root
    sudo cp -r $HOME/yiimp/bin/. /bin/
    sudo cp -r $HOME/yiimp/blocknotify/blocknotify /usr/bin/
    sudo cp -r $HOME/yiimp/blocknotify/blocknotify /var/stratum/
    sudo mkdir -p /etc/yiimp
    sudo mkdir -p $HOME/backup/
    #fixing yiimp
    sed -i "s|/root=/data/yiimp|ROOTDIR=/var|g" /bin/yiimp
    #fixing run.sh
    sudo rm -r /var/stratum/config/run.sh
   echo '
#!/bin/bash
ulimit -n 10240
ulimit -u 10240
cd /var/stratum
while true; do
        ./stratum /var/stratum/config/$1
        sleep 2
done
exec bash
' | sudo -E tee /var/stratum/config/run.sh >/dev/null 2>&1
sudo chmod +x /var/stratum/config/run.sh


    output " "
    output "Update default timezone."
    output " "

    # check if link file
    sudo [ -L /etc/localtime ] &&  sudo unlink /etc/localtime

    # update time zone
    sudo ln -sf /usr/share/zoneinfo/$TIME /etc/localtime
    sudo aptitude -y install ntpdate

    # write time to clock.
    sudo hwclock -w

    output " "
    output "Making Web Server Magic Happen!"
    output " "
    # adding user to group, creating dir structure, setting permissions
    sudo mkdir -p /var/www/$server_name/html 


    output " "
    output "Creating webserver initial config file"
    output " "
    if [[ ("$sub_domain" == "y" || "$sub_domain" == "Y") ]]; then
    echo 'include /etc/nginx/blockuseragents.rules;
   server {
   if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"';
        root "/var/www/'"${server_name}"'/html/web";
        index index.html index.htm index.php;
        charset utf-8;
    
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        location = /favicon.ico { access_log off; log_not_found off; }
        location = /robots.txt  { access_log off; log_not_found off; }
    
        access_log off;
        error_log  /var/log/nginx/'"${server_name}"'.app-error.log error;
    
        # allow larger file uploads and longer script runtimes
   client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
    
        location ~ ^/index\.php$ {
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_intercept_errors off;
            fastcgi_buffer_size 16k;
            fastcgi_buffers 4 16k;
            fastcgi_connect_timeout 300;
            fastcgi_send_timeout 300;
            fastcgi_read_timeout 300;
       try_files $uri $uri/ =404;
        }
      location ~ \.php$ {
         return 404;
        }
      location ~ \.sh {
      return 404;
        }
      location ~ /\.ht {
      deny all;
        }
      location ~ /.well-known {
      allow all;
        }
      location /phpmyadmin {
      root /usr/share/;
      index index.php;
      try_files $uri $uri/ =404;
      location ~ ^/phpmyadmin/(doc|sql|setup)/ {
         deny all;
   }
      location ~ /phpmyadmin/(.+\.php)$ {
         fastcgi_pass unix:/run/php/php7.3-fpm.sock;
         fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
         include fastcgi_params;
         include snippets/fastcgi-php.conf;
   }
 }
 }
' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1

    sudo ln -s /etc/nginx/sites-available/$server_name.conf /etc/nginx/sites-enabled/$server_name.conf
    sudo ln -s /var/web /var/www/$server_name/html
    #sudo service nginx restart
    sudo supervisorctl restart nginx
    if [[ ("$ssl_install" == "y" || "$ssl_install" == "Y" || "$ssl_install" == "") ]]; then

    output " "
    output "Install LetsEncrypt and setting SSL"
    output " "

    sudo aptitude -y install letsencrypt
    sudo letsencrypt certonly -a webroot --webroot-path=/var/web --email "$EMAIL" --agree-tos -d "$server_name"
    sudo rm /etc/nginx/sites-available/$server_name.conf
    sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    # I am SSL Man!
   echo 'include /etc/nginx/blockuseragents.rules;
   server {
   if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"';
      # enforce https
        return 301 https://$server_name$request_uri;
   }
   
   server {
   if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
            listen 443 ssl http2;
            listen [::]:443 ssl http2;
            server_name '"${server_name}"';
        
            root /var/www/'"${server_name}"'/html/web;
            index index.php;
        
            access_log /var/log/nginx/'"${server_name}"'.app-accress.log;
            error_log  /var/log/nginx/'"${server_name}"'.app-error.log error;
        
            # allow larger file uploads and longer script runtimes
   client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
        
            # strengthen ssl security
            ssl_certificate /etc/letsencrypt/live/'"${server_name}"'/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/'"${server_name}"'/privkey.pem;
            ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
            ssl_prefer_server_ciphers on;
            ssl_session_cache shared:SSL:10m;
            ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
            ssl_dhparam /etc/ssl/certs/dhparam.pem;
        
            # Add headers to serve security related headers
            add_header Strict-Transport-Security "max-age=15768000; preload;";
            add_header X-Content-Type-Options nosniff;
            add_header X-XSS-Protection "1; mode=block";
            add_header X-Robots-Tag none;
            add_header Content-Security-Policy "frame-ancestors 'self'";
        
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        
            location ~ ^/index\.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
                fastcgi_index index.php;
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_intercept_errors off;
                fastcgi_buffer_size 16k;
                fastcgi_buffers 4 16k;
                fastcgi_connect_timeout 300;
                fastcgi_send_timeout 300;
                fastcgi_read_timeout 300;
                include /etc/nginx/fastcgi_params;
         try_files $uri $uri/ =404;
        }
      location ~ \.php$ {
         return 404;
        }
      location ~ \.sh {
      return 404;
        }
        
            location ~ /\.ht {
                deny all;
            }
       location /phpmyadmin {
      root /usr/share/;
      index index.php;
      try_files $uri $uri/ =404;
      location ~ ^/phpmyadmin/(doc|sql|setup)/ {
         deny all;
   }
      location ~ /phpmyadmin/(.+\.php)$ {
         fastcgi_pass unix:/run/php/php7.3-fpm.sock;
         fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
         include fastcgi_params;
         include snippets/fastcgi-php.conf;
   }
 }
 }
        
' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1
   fi
   #sudo service nginx restart
   sudo supervisorctl restart nginx
   sudo service php7.3-fpm reload
   else
   echo 'include /etc/nginx/blockuseragents.rules;
   server {
   if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"' www.'"${server_name}"';
        root "/var/www/'"${server_name}"'/html/web";
        index index.html index.htm index.php;
        charset utf-8;
    
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        location = /favicon.ico { access_log off; log_not_found off; }
        location = /robots.txt  { access_log off; log_not_found off; }
    
        access_log off;
        error_log  /var/log/nginx/'"${server_name}"'.app-error.log error;
    
        # allow larger file uploads and longer script runtimes
   client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
    
        location ~ ^/index\.php$ {
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_intercept_errors off;
            fastcgi_buffer_size 16k;
            fastcgi_buffers 4 16k;
            fastcgi_connect_timeout 300;
            fastcgi_send_timeout 300;
            fastcgi_read_timeout 300;
       try_files $uri $uri/ =404;
        }
      location ~ \.php$ {
         return 404;
        }
      location ~ \.sh {
      return 404;
        }
      location ~ /\.ht {
      deny all;
        }
      location ~ /.well-known {
      allow all;
        }
      location /phpmyadmin {
      root /usr/share/;
      index index.php;
      try_files $uri $uri/ =404;
      location ~ ^/phpmyadmin/(doc|sql|setup)/ {
         deny all;
   }
      location ~ /phpmyadmin/(.+\.php)$ {
         fastcgi_pass unix:/run/php/php7.3-fpm.sock;
         fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
         include fastcgi_params;
         include snippets/fastcgi-php.conf;
   }
 }
 }
' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1

    sudo ln -s /etc/nginx/sites-available/$server_name.conf /etc/nginx/sites-enabled/$server_name.conf
    sudo ln -s /var/web /var/www/$server_name/html
    #sudo service nginx restart
    sudo supervisorctl restart nginx
    if [[ ("$ssl_install" == "y" || "$ssl_install" == "Y" || "$ssl_install" == "") ]]; then

    output " "
    output "Install LetsEncrypt and setting SSL"
    output " "
    sleep 3

    sudo aptitude -y install letsencrypt
    sudo letsencrypt certonly -a webroot --webroot-path=/var/web --email "$EMAIL" --agree-tos -d "$server_name" -d www."$server_name"
    sudo rm /etc/nginx/sites-available/$server_name.conf
    sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    # I am SSL Man!
   echo 'include /etc/nginx/blockuseragents.rules;
   server {
   if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${server_name}"';
      # enforce https
        return 301 https://$server_name$request_uri;
   }
   
   server {
   if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
            listen 443 ssl http2;
            listen [::]:443 ssl http2;
            server_name '"${server_name}"' www.'"${server_name}"';
        
            root /var/www/'"${server_name}"'/html/web;
            index index.php;
        
            access_log /var/log/nginx/'"${server_name}"'.app-accress.log;
            error_log  /var/log/nginx/'"${server_name}"'.app-error.log error;
        
            # allow larger file uploads and longer script runtimes
   client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
        
            # strengthen ssl security
            ssl_certificate /etc/letsencrypt/live/'"${server_name}"'/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/'"${server_name}"'/privkey.pem;
            ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
            ssl_prefer_server_ciphers on;
            ssl_session_cache shared:SSL:10m;
            ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
            ssl_dhparam /etc/ssl/certs/dhparam.pem;
        
            # Add headers to serve security related headers
            add_header Strict-Transport-Security "max-age=15768000; preload;";
            add_header X-Content-Type-Options nosniff;
            add_header X-XSS-Protection "1; mode=block";
            add_header X-Robots-Tag none;
            add_header Content-Security-Policy "frame-ancestors 'self'";
        
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        
            location ~ ^/index\.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
                fastcgi_index index.php;
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_intercept_errors off;
                fastcgi_buffer_size 16k;
                fastcgi_buffers 4 16k;
                fastcgi_connect_timeout 300;
                fastcgi_send_timeout 300;
                fastcgi_read_timeout 300;
                include /etc/nginx/fastcgi_params;
         try_files $uri $uri/ =404;
        }
      location ~ \.php$ {
         return 404;
        }
      location ~ \.sh {
      return 404;
        }
        
            location ~ /\.ht {
                deny all;
            }
       location /phpmyadmin {
      root /usr/share/;
      index index.php;
      try_files $uri $uri/ =404;
      location ~ ^/phpmyadmin/(doc|sql|setup)/ {
         deny all;
   }
      location ~ /phpmyadmin/(.+\.php)$ {
         fastcgi_pass unix:/run/php/php7.3-fpm.sock;
         fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
         include fastcgi_params;
         include snippets/fastcgi-php.conf;
   }
 }
 }
        
' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1
   fi
   #sudo service nginx restart
   sudo supervisorctl restart nginx
   sudo service php7.3-fpm reload
   fi

    output " "
    output "Now for the database fun!"
    output " "
    service mysql start
    sleep 3

    # create database
    Q1="CREATE DATABASE IF NOT EXISTS yiimpfrontend;"
    Q2="GRANT ALL ON *.* TO 'panel'@'localhost' IDENTIFIED BY '$password';"
    Q3="FLUSH PRIVILEGES;"
    SQL="${Q1}${Q2}${Q3}"
    sudo mysql -u root -p="" -e "$SQL"

    # create stratum user
    Q1="GRANT ALL ON *.* TO 'stratum'@'localhost' IDENTIFIED BY '$password2';"
    Q2="FLUSH PRIVILEGES;"
    SQL="${Q1}${Q2}"
    sudo mysql -u root -p="" -e "$SQL"  

    #Create my.cnf

 echo '
[clienthost1]
user=panel
password='"${password}"'
database=yiimpfrontend
host=localhost
[clienthost2]
user=stratum
password='"${password2}"'
database=yiimpfrontend
host=localhost
[myphpadmin]
user=phpmyadmin
password='"${AUTOGENERATED_PASS}"'
[mysql]
user=root
password='"${rootpasswd}"'
' | sudo -E tee ~/.my.cnf >/dev/null 2>&1
      sudo chmod 0600 ~/.my.cnf

#Create keys file
  echo '  
    <?php
/* Sample config file to put in /etc/yiimp/keys.php */
define('"'"'YIIMP_MYSQLDUMP_USER'"'"', '"'"'panel'"'"');
define('"'"'YIIMP_MYSQLDUMP_PASS'"'"', '"'"''"${password}"''"'"');
/* Keys required to create/cancel orders and access your balances/deposit addresses */
define('"'"'EXCH_BITTREX_SECRET'"'"', '"'"'<my_bittrex_api_secret_key>'"'"');
define('"'"'EXCH_BITSTAMP_SECRET'"'"','"'"''"'"');
define('"'"'EXCH_BLEUTRADE_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_BTER_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_CCEX_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_COINMARKETS_PASS'"'"', '"'"''"'"');
define('"'"'EXCH_CRYPTOPIA_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_EMPOEX_SECKEY'"'"', '"'"''"'"');
define('"'"'EXCH_HITBTC_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_KRAKEN_SECRET'"'"','"'"''"'"');
define('"'"'EXCH_LIVECOIN_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_NOVA_SECRET'"'"','"'"''"'"');
define('"'"'EXCH_POLONIEX_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_YOBIT_SECRET'"'"', '"'"''"'"');
' | sudo -E tee /etc/yiimp/keys.php >/dev/null 2>&1


    output " "
    output "Database 'yiimpfrontend' and users 'panel' and 'stratum' created with password $password and $password2, will be saved for you"
    output " "
    output "Peforming the SQL import"
    output " "
    sleep 3

    cd ~
    cd PoolColeganet/sql

    # import sql dump
    sudo zcat 2016-04-03-yaamp.sql.gz | sudo mysql --defaults-group-suffix=host1

    # oh the humanity!
    sudo mysql --defaults-group-suffix=host1 --force < 2016-04-24-market_history.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-04-27-settings.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-05-11-coins.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-05-15-benchmarks.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-05-23-bookmarks.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-06-01-notifications.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-06-04-bench_chips.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2016-11-23-coins.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-02-05-benchmarks.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-03-31-earnings_index.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-05-accounts_case_swaptime.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-06-payouts_coinid_memo.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-09-notifications.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-10-bookmarks.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2017-11-segwit.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2018-01-stratums_ports.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2018-02-coins_getinfo.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2018-09-22-workers.sql
    sudo mysql --defaults-group-suffix=host1 --force < 2020-06-03-blocks.sql
    output " "
    output "Generating a basic serverconfig.php"
    output " "
    sleep 3

    # make config file
echo '
<?php
ini_set('"'"'date.timezone'"'"', '"'"'UTC'"'"');
define('"'"'YAAMP_LOGS'"'"', '"'"'/var/log'"'"');
define('"'"'YAAMP_HTDOCS'"'"', '"'"'/var/web'"'"');
define('"'"'YAAMP_BIN'"'"', '"'"'/var/bin'"'"');
define('"'"'YAAMP_DBHOST'"'"', '"'"'localhost'"'"');
define('"'"'YAAMP_DBNAME'"'"', '"'"'yiimpfrontend'"'"');
define('"'"'YAAMP_DBUSER'"'"', '"'"'panel'"'"');
define('"'"'YAAMP_DBPASSWORD'"'"', '"'"''"${password}"''"'"');
define('"'"'YAAMP_PRODUCTION'"'"', true);
define('"'"'YAAMP_RENTAL'"'"', false);
define('"'"'YAAMP_LIMIT_ESTIMATE'"'"', false);
define('"'"'YAAMP_FEES_MINING'"'"', 0.5);
define('"'"'YAAMP_FEES_EXCHANGE'"'"', 2);
define('"'"'YAAMP_FEES_RENTING'"'"', 2);
define('"'"'YAAMP_TXFEE_RENTING_WD'"'"', 0.002);
define('"'"'YAAMP_PAYMENTS_FREQ'"'"', 2*60*60);
define('"'"'YAAMP_PAYMENTS_MINI'"'"', 0.001);
define('"'"'YAAMP_ALLOW_EXCHANGE'"'"', false);
define('"'"'YIIMP_PUBLIC_EXPLORER'"'"', true);
define('"'"'YIIMP_PUBLIC_BENCHMARK'"'"', true);
define('"'"'YIIMP_FIAT_ALTERNATIVE'"'"', '"'"'USD'"'"'); // USD is main
define('"'"'YAAMP_USE_NICEHASH_API'"'"', false);
define('"'"'YAAMP_BTCADDRESS'"'"', '"'"' '"'"');
define('"'"'YAAMP_SITE_URL'"'"', '"'"''"${server_name}"''"'"');
define('"'"'YAAMP_STRATUM_URL'"'"', YAAMP_SITE_URL); // change if your stratum server is on a different host
define('"'"'YAAMP_SITE_NAME'"'"', '"'"'Coleganet'"'"');
define('"'"'YAAMP_ADMIN_EMAIL'"'"', '"'"''"${EMAIL}"''"'"');
define('"'"'YAAMP_ADMIN_IP'"'"', '"'"''"${Public}"''"'"'); // samples: "80.236.118.26,90.234.221.11" or "10.0.0.1/8"
define('"'"'YAAMP_ADMIN_WEBCONSOLE'"'"', true);
define('"'"'YAAMP_NOTIFY_NEW_COINS'"'"', false);
define('"'"'YAAMP_DEFAULT_ALGO'"'"', '"'"'x16r'"'"');
define('"'"'YAAMP_USE_NGINX'"'"', true);
// Exchange public keys (private keys are in a separate config file)
define('"'"'EXCH_CRYPTOPIA_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_POLONIEX_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_BITTREX_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_BLEUTRADE_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_BTER_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_YOBIT_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_CCEX_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_COINMARKETS_USER'"'"', '"'"''"'"');
define('"'"'EXCH_COINMARKETS_PIN'"'"', '"'"''"'"');
define('"'"'EXCH_BITSTAMP_ID'"'"','"'"''"'"');
define('"'"'EXCH_BITSTAMP_KEY'"'"','"'"''"'"');
define('"'"'EXCH_HITBTC_KEY'"'"','"'"''"'"');
define('"'"'EXCH_KRAKEN_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_LIVECOIN_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_NOVA_KEY'"'"', '"'"''"'"');
// Automatic withdraw to Yaamp btc wallet if btc balance > 0.3
define('"'"'EXCH_AUTO_WITHDRAW'"'"', 0.3);
// nicehash keys deposit account & amount to deposit at a time
define('"'"'NICEHASH_API_KEY'"'"','"'"' '"'"');
define('"'"'NICEHASH_API_ID'"'"','"'"' '"'"');
define('"'"'NICEHASH_DEPOSIT'"'"','"'"' '"'"');
define('"'"'NICEHASH_DEPOSIT_AMOUNT'"'"','"'"'0.01'"'"');
$cold_wallet_table = array(
   '"'"' '"'"' => 0.10,
);
// Sample fixed pool fees
$configFixedPoolFees = array(
        '"'"'zr5'"'"' => 2.0,
        '"'"'scrypt'"'"' => 20.0,
        '"'"'sha256'"'"' => 5.0,
);
// Sample custom stratum ports
$configCustomPorts = array(
// '"'"'x11'"'"' => 7000,
);
// mBTC Coefs per algo (default is 1.0)
$configAlgoNormCoef = array(
// '"'"'x11'"'"' => 5.0,
);
' | sudo -E tee /var/web/serverconfig.php >/dev/null 2>&1

output " "
output "Updating stratum config files with database connection info."
output " "
sleep 3

cd /var/stratum/config
sudo sed -i 's/password = tu8tu5/password = '$blckntifypass'/g' *.conf
sudo sed -i 's/server = yaamp.com/server = '$server_name'/g' *.conf
sudo sed -i 's/host = yaampdb/host = localhost/g' *.conf
sudo sed -i 's/database = yaamp/database = yiimpfrontend/g' *.conf
sudo sed -i 's/username = root/username = stratum/g' *.conf
sudo sed -i 's/password = patofpaq/password = '$password2'/g' *.conf
cd ~

output " "
output "Final Directory permissions"
output " "
sleep 3

whoami=`whoami`
#sudo mkdir /root/backup/
#sudo usermod -aG www-data $whoami
#sudo chown -R www-data:www-data /var/log
sudo chown -R www-data:www-data /var/stratum
sudo chown -R www-data:www-data /var/web
sudo touch /var/log/debug.log
sudo chown -R www-data:www-data /var/log/debug.log
sudo chmod -R 775 /var/www/$server_name/html
sudo chmod -R 775 /var/web
sudo chmod -R 775 /var/stratum
sudo chmod -R 775 /var/web/yaamp/runtime
sudo chmod -R 664 /root/backup/
sudo chmod -R 644 /var/log/debug.log
sudo chmod -R 775 /var/web/serverconfig.php
output " "
output "Now for Install the Startup Scripts take a little expresso and have fun!"
output " "
apt install lsb-release figlet update-motd landscape-common update-notifier-common
sudo mv /home/yiimp/ /home/coleganet-install-only-do-not-run-commands-from-this-folder
#sudo service nginx restart
sudo supervisorctl restart nginx
sudo service php7.3-fpm reload
output "Installing Server Manager Webmin"
echo "deb http://download.webmin.com/download/repository sarge contrib" >> /etc/apt/sources.list
wget -q -O- http://www.webmin.com/jcameron-key.asc | sudo apt-key add
sudo apt-get update
sudo apt install webmin
output "********************************************* "
output "Visit https://yourserver.com:10000 for use your server manager user root password your password "
output "Update Memcached flux use every time you make template changes "
sed -i -e '$a## bash shortcut Mencached Flush ##' ~/.bashrc
sed -i -e '$aalias flush_mem_cache_server="echo 'flush_all' | netcat 127.0.0.1 11211"' ~/.bashrc
output "Use the command mflush for clean memcached "
sudo apt-get -y install apache2-utils
output "Installing Apache Utils You will need for protect Admin folder with a password please read inside scripts folder the document Admin"
 #Restart service
    sudo service cron restart
    sudo servicet mysql restart
    sudo service mysql status | sed -n "1,3p"
    sudo supervisorctl restart nginx
    sudo service nginx status | sed -n "1,3p"
    sudo supervisorctl restart php7.3-fpm
    service php7.3-fpm status | sed -n "1,3p"

    echo
    echo -e "$GREEN Done...$COL_RESET"
    sleep 3

    echo
    echo
    echo
    echo -e "$GREEN***************************$COL_RESET"
    echo -e "$GREEN Yiimp Install Script v0.2 $COL_RESET"
    echo -e "$GREEN Finish !!! $COL_RESET"
    echo -e "$GREEN***************************$COL_RESET"
    echo 
    echo
    echo
    echo -e "$CYAN Whew that was fun, just some reminders. $COL_RESET" 
    echo -e "$RED Your mysql information is saved in ~/.my.cnf. $COL_RESET"
    echo
    echo -e "$RED Yiimp at : http://"$server_name" (https... if SSL enabled)"
    echo -e "$RED Yiimp Admin at : http://"$server_name"/site/AdminPanel (https... if SSL enabled)"
    echo -e "$RED Yiimp phpMyAdmin at : http://"$server_name"/phpmyadmin (https... if SSL enabled)"
    echo
    echo -e "$RED If you want change 'AdminPanel' to access Panel Admin : Edit this file : /var/web/yaamp/modules/site/SiteController.php"
    echo -e "$RED Line 11 => change 'AdminPanel' and use the new address"
    echo
    echo -e "$CYAN Please make sure to change your public keys / wallet addresses in the /var/web/serverconfig.php file. $COL_RESET"
    echo -e "$CYAN Please make sure to change your private keys in the /etc/yiimp/keys.php file. $COL_RESET"
    echo
    echo -e "$RED***************************************************$COL_RESET"
    echo -e "$RED YOU MUST REBOOT NOW  TO FINALIZE INSTALLATION !!! $COL_RESET"
    echo -e "$RED***************************************************$COL_RESET"
    echo
    echo
