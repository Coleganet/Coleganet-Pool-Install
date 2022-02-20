#!/bin/bash

host -t srv _ldap._tcp.$1 | grep "has SRV record" >/dev/null || {
    echo "FATAL: Your dns are not corrector your DNS servers are broken."
    exit 2
}
bash goinstall.sh

