#Starttup script

sudo killall screen
sudo screen -dmS main $WEB_DIR/main.sh
sudo screen -dmS loop2 $WEB_DIR/loop2.sh
sudo screen -dmS blocks $WEB_DIR/blocks.sh
# Stratum instances

#sudo screen -dmS [algoname] $STRATUM_DIR/run.sh [algoname]
