#!/bin/bash

# Suppresion des VM 
# SD 2025
# ne pas supprimer la VM500

START_ID=$1
END_ID=$2
DRYRUN=$3   # mettre "dry" en 3e argument pour test

if [ -z "$START_ID" ] || [ -z "$END_ID" ]; then
  echo "Usage: $0 <start_id> <end_id> [dry]"
  exit 1
fi

echo "Suppression des IDs de $START_ID à $END_ID"
[ "$DRYRUN" = "dry" ] && echo "MODE TEST (aucune suppression)"

read -p "Confirmer ? (yes/no) : " CONFIRM
[ "$CONFIRM" != "yes" ] && exit 0

for ((ID=START_ID; ID<=END_ID; ID++)); do

  if qm status $ID &>/dev/null; then
    echo "VM détectée: $ID"
    if [ "$DRYRUN" != "dry" ]; then
      qm stop $ID --skiplock 2>/dev/null
      qm destroy $ID --purge
    fi

  elif pct status $ID &>/dev/null; then
    echo "LXC détecté: $ID"
    if [ "$DRYRUN" != "dry" ]; then
      pct stop $ID 2>/dev/null
      pct destroy $ID --purge
    fi

  else
    echo "ID $ID inexistant"
  fi

done

echo "Terminé."
