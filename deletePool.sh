#!/bin/bash

# suppression de tous les pools
# SD 2026
# installer :
# apt-get install jq

read -p "Supprimer TOUS les pools Proxmox ? (yes/no) : " CONFIRM
[ "$CONFIRM" != "yes" ] && exit 0

pvesh get /pools --output-format json \
| jq -r '.[].poolid' \
| while read -r POOL; do
    echo "Suppression du pool: $POOL"
    pveum pool delete "$POOL"
  done

echo "Terminé."
