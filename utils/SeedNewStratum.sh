# Installing Stratum Upgrade
    echo
    echo
    echo -e "$CYAN => Script for Installing a update version of Stratum with extra coins $COL_RESET"
    echo
    echo -e "Building files and setting file structure."
    echo
    sleep 3

# Generating Random Password for stratum
    blckntifypass=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1`
    
    # Compil Blocknotify
    cd ~
    hide_output git clone https://github.com/tpruvot/yiimp
    cd $HOME/yiimp/blocknotify
    sudo sed -i 's/tu8tu5/'$blckntifypass'/' blocknotify.cpp
    hide_output sudo make


# Compil iniparser
    cd $HOME/stratum/iniparser
    hide_output sudo make
    
    # Compil Stratum
    cd $HOME/stratum
    if [[ ("$BTC" == "y" || "$BTC" == "Y") ]]; then
    sudo sed -i 's/CFLAGS += -DNO_EXCHANGE/#CFLAGS += -DNO_EXCHANGE/' $HOME/stratum/Makefile
    fi
    hide_output sudo make
 
 # Updating stratum config files with database connection info
    echo
    echo
    echo -e "$CYAN => Updating stratum config files with database connection info. $COL_RESET"
    echo
    sleep 3
    
    cp $HOME/yiimp-install-only-do-not-run-commands-from-this-folder/stratum/config /var/stratum/config
    cd /var/stratum/config
    sudo sed -i 's/password = tu8tu5/password = '$blckntifypass'/g' *.conf
    sudo sed -i 's/server = yaamp.com/server = '$server_name'/g' *.conf
    sudo sed -i 's/host = yaampdb/host = localhost/g' *.conf
    sudo sed -i 's/database = yaamp/database = yiimpfrontend/g' *.conf
    sudo sed -i 's/username = root/username = stratum/g' *.conf
    sudo sed -i 's/password = patofpaq/password = '$password2'/g' *.conf
    cd ~
    echo -e "$GREEN Done...$COL_RESET"
    
    # Copy Files (Blocknotify,iniparser,Stratum)
    cd $HOME/yiimp
    sudo mv /var/stratum /var/stratum/old
    sudo mkdir -p /var/stratum
    cd $HOME/yiimp-install-only-do-not-run-commands-from-this-folder/stratum
    sudo cp -a config.sample/. /var/stratum/config
    sudo cp -r stratum /var/stratum
    sudo cp -r run.sh /var/stratum
    cd $HOME/yiimp
    sudo cp -r $HOME/yiimp/bin/. /bin/
    sudo cp -r $HOME/yiimp/blocknotify/blocknotify /usr/bin/
    sudo cp -r $HOME/yiimp/blocknotify/blocknotify /var/stratum/
    sudo mkdir -p /etc/yiimp
