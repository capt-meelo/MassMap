#!/bin/bash

VERSION="2.0"

TARGET="$1"

WORKING_DIR="$(cd "$(dirname "$0")" ; pwd -P)"
RESULTS_PATH="$WORKING_DIR/results"

RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"


displayLogo(){
echo -e "${GREEN}                               
 _______                     _______              
|   |   |.---.-.-----.-----.|   |   |.---.-.-----.
|       ||  _  |__ --|__ --||       ||  _  |  _  |
|__|_|__||___._|_____|_____||__|_|__||___._|   __|${RESET} ${RED}v$VERSION${RESET}  
                                           ${GREEN}|__|${RESET}    by ${YELLOW}@CaptMeelo${RESET}\n
"
}


checkArgs(){
    if [[ $# -eq 0 ]]; then
        echo -e "\t${RED}[!] ERROR:${RESET} Invalid argument!\n"
        echo -e "\t${GREEN}[+] USAGE:${RESET}$0 <file-containing-list-of-IP/CIDR>\n"
        exit 1
    elif [ ! -s $1 ]; then
        echo -e "\t${RED}[!] ERROR:${RESET} File is empty and/or does not exists!\n"
        echo -e "\t${GREEN}[+] USAGE:${RESET}$0 <file-containing-list-of-IP/CIDR>\n"
        exit 1
    fi
}

portScan(){
    echo -e "${GREEN}[+] Checking if results directory already exists.${RESET}"
    if [ -d $RESULTS_PATH ]
    then
        echo -e "${BLUE}[-] Directory already exists. Skipping...${RESET}"
    else
        echo -e "${GREEN}[+] Creating results directory.${RESET}"
        mkdir -p $RESULTS_PATH
    fi

    echo -e "${GREEN}[+] Running Masscan.${RESET}"
    sudo masscan -p 1-65535 --rate 100000 --wait 0 --open -iL $TARGET -oX $RESULTS_PATH/masscan.xml
    if [ -f "$WORKING_DIR/paused.conf" ] ; then
        sudo rm "$WORKING_DIR/paused.conf"
    fi
    open_ports=$(cat $RESULTS_PATH/masscan.xml | grep portid | cut -d "\"" -f 10 | sort -n | uniq | paste -sd,)
    cat $RESULTS_PATH/masscan.xml | grep portid | cut -d "\"" -f 4 | sort -V | uniq > $WORKING_DIR/nmap_targets.tmp
    echo -e "${RED}[*] Masscan Done!"

    echo -e "${GREEN}[+] Running Nmap.${RESET}"
    sudo nmap -sVC -p $open_ports --open -v -Pn -n -T4 -iL $WORKING_DIR/nmap_targets.tmp -oX $RESULTS_PATH/nmap.xml
    sudo rm $WORKING_DIR/nmap_targets.tmp
    xsltproc -o $RESULTS_PATH/nmap-native.html $RESULTS_PATH/nmap.xml
    xsltproc -o $RESULTS_PATH/nmap-bootstrap.html $WORKING_DIR/bootstrap-nmap.xsl $RESULTS_PATH/nmap.xml
    echo -e "${RED}[*] Nmap Done! View the HTML reports at $RESULTS_PATH${RESET}"
}


displayLogo
checkArgs $TARGET
portScan