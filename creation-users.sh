#!/bin/bash
# ======================================================
# Script : creation-users.sh
# Objectif : Créer comptes utilisateurs Proxmox
#            NAT IPv4 via nftables, DHCP, SDN
#            Option : --reset-nft pour purger règles NFT existantes
# Auteur : SD 2025
# Usage : ./creation-user-nat-dhcp-sdn.sh users.txt [--reset-nft]
# Format users.txt : username;password
# ======================================================

USERFILE="$1"
RESET_NFT="$2"
PROXMOX_IP="172.17.50.248" #"192.168.0.23" 
BRIDGE="vmbr1"
BRIDGE_NET="192.168.100.0/24"
BRIDGE_GW="192.168.100.1"
EXTERNAL_IF="vmbr0"
VM_NET_START=10
VM_NET_STOP=210
NODE=$(hostname)
SDN_ZONE="studZ"
SDN_VNET="studV"

# Groupe global pour templates de VM
#GROUP_TEMPLATES="templates-access"

# Crée le groupe global templates-access si inexistant
#pveum group list | grep -q "$GROUP_TEMPLATES" || pveum group add "$GROUP_TEMPLATES"


if [[ ! -f "$USERFILE" ]]; then
  echo "❌ Fichier $USERFILE introuvable."
  echo "Format attendu : username;password;PORT1;PORT2;PORT3"
  exit 1
fi

# Option --reset-nft : purge des anciennes tables
if [[ "$RESET_NFT" == "--reset-nft" ]]; then
    echo "⚠️ Suppression des anciennes tables nftables..."
    nft delete table ip proxmox_nat 2>/dev/null
    nft delete table ip proxmox_filter 2>/dev/null
    echo "✅ Anciennes tables nftables supprimées."
fi

# === Création du bridge interne ===
 if ! ip link show "$BRIDGE" &>/dev/null; then
    echo "🌐 Création du bridge interne $BRIDGE..."
    ip link add name $BRIDGE type bridge
    ip addr add ${BRIDGE_GW}/24 dev $BRIDGE
    ip link set $BRIDGE up

    echo "✅ Bridge $BRIDGE créé et activé."
else
    echo "ℹ️ Bridge $BRIDGE déjà existant."
fi

if ! grep -q "^auto $BRIDGE" /etc/network/interfaces; then
    cat <<EOF >> /etc/network/interfaces

auto $BRIDGE
iface $BRIDGE inet static
    address $BRIDGE_GW
    netmask 255.255.255.0
    bridge-ports none
    bridge-stp off
    bridge-fd 0
EOF
fi

# --- Forcer le mode static pour vmbr1 si 'manual' existe ---
if grep -q "^iface $BRIDGE inet manual" /etc/network/interfaces; then
   sed -i "s/^iface $BRIDGE inet manual/iface $BRIDGE inet static\n    address $BRIDGE_GW\n    netmask 255.255.255.0/" /etc/network/interfaces
fi

echo "🔄 Rechargement configuration réseau..."
ifreload -a || systemctl restart networking


# === DHCP via dnsmasq ===
echo "🌐 Installation et configuration de DHCP sur $BRIDGE..."
apt install -y dnsmasq
mkdir -p /etc/dnsmasq.d
cat <<EOF >/etc/dnsmasq.d/$BRIDGE.conf
interface=$BRIDGE
bind-interfaces
dhcp-range=192.168.100.10,192.168.100.210,12h
dhcp-option=3,$BRIDGE_GW
dhcp-option=6,8.8.8.8
EOF
systemctl enable dnsmasq
systemctl restart dnsmasq && echo "✅ DHCP activé sur $BRIDGE."

# === NAT IPv4 avec nftables ===
echo "🔄 Configuration NAT IPv4 avec nftables ..."
sysctl -w net.ipv4.ip_forward=1
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

apt install -y nftables
systemctl enable nftables
systemctl start nftables

mkdir -p /etc/nftables.d
PROXMOX_NAT_CONF="/etc/nftables.d/proxmox_nat.conf"


# Création des tables et chaines si inexistantes
nft list table ip proxmox_nat >/dev/null 2>&1 || nft 'add table ip proxmox_nat'
nft list chain ip proxmox_nat prerouting >/dev/null 2>&1 || \
  nft 'add chain ip proxmox_nat prerouting { type nat hook prerouting priority -100; policy accept; }'
nft list chain ip proxmox_nat postrouting >/dev/null 2>&1 || \
  nft "add chain ip proxmox_nat postrouting { type nat hook postrouting priority 100; policy accept; }"

# Masquerade pour NAT source
nft list chain ip proxmox_nat postrouting | grep -q "oifname \"$EXTERNAL_IF\" ip saddr $BRIDGE_NET masquerade" || \
  nft add rule ip proxmox_nat postrouting oifname "$EXTERNAL_IF" ip saddr $BRIDGE_NET masquerade


# Table filter pour le forwarding
nft list chain ip proxmox_filter forward | grep -q "iifname \"$BRIDGE\" oifname \"$EXTERNAL_IF\" accept" || \
  nft add rule ip proxmox_filter forward iifname "$BRIDGE" oifname "$EXTERNAL_IF" accept
nft list chain ip proxmox_filter forward | grep -q "iifname \"$EXTERNAL_IF\" oifname \"$BRIDGE\" ct state established,related accept" || \
  nft add rule ip proxmox_filter forward iifname "$EXTERNAL_IF" oifname "$BRIDGE" ct state established,related accept


# Autoriser le forwarding LAN <-> WAN
nft add rule ip proxmox_filter forward iifname "$BRIDGE" oifname "$EXTERNAL_IF" accept 2>/dev/null
nft add rule ip proxmox_filter forward iifname "$EXTERNAL_IF" oifname "$BRIDGE" ct state established,related accept 2>/dev/null


cat <<EOF > "$PROXMOX_NAT_CONF"
table ip proxmox_nat {
    chain prerouting {
        type nat hook prerouting priority -100;
    }
    chain postrouting {
        type nat hook postrouting priority 100;
        oifname "$EXTERNAL_IF" ip saddr $BRIDGE_NET masquerade
    }
}

table ip proxmox_filter {
    chain forward {
        type filter hook forward priority 0;
        ct state established,related accept
        iifname "$BRIDGE" oifname "$EXTERNAL_IF" accept
		iifname "$EXTERNAL_IF" oifname "$BRIDGE" accept
        iifname "$EXTERNAL_IF" oifname "$BRIDGE" ct state established,related accept
    }
}
EOF

# Inclusion automatique dans /etc/nftables.conf
if ! grep -q "/etc/nftables.d/proxmox_nat.conf" /etc/nftables.conf 2>/dev/null; then
    echo "include \"/etc/nftables.d/proxmox_nat.conf\"" >> /etc/nftables.conf
fi

# Charger les règles
nft -f "$PROXMOX_NAT_CONF"
systemctl restart nftables
echo "✅ NAT et forwarding IPv4 configurés avec nftables."




# === SDN ===
echo "🌐 Création zone et VNet SDN..."
if ! pvesh get /cluster/sdn/zones | grep -q "$SDN_ZONE"; then
    echo "🌐 Création zone SDN $SDN_ZONE..."
    pvesh create /cluster/sdn/zones -zone $SDN_ZONE -type simple
    echo "✅ Zone SDN créée."
else
    echo "ℹ️ Zone SDN $SDN_ZONE déjà existante."
fi

if ! pvesh get /cluster/sdn/vnets | grep -q "$SDN_VNET"; then
    echo "🌐 Création VNet SDN $SDN_VNET..."
    pvesh create /cluster/sdn/vnets -vnet $SDN_VNET -zone $SDN_ZONE
    echo "✅ VNet SDN créé."
else
    echo "ℹ️ VNet SDN $SDN_VNET déjà existant."
fi

# === Rôles ===
echo "🔄 Création / mise à jour des rôles..."
declare -A roles
roles=(  # VM.Monitor existe plus dans version 9 de proxmox
  ["LimitedVMAdmin"]="VM.Allocate VM.Audit VM.Clone VM.Console VM.Config.CDROM VM.Config.Cloudinit VM.Config.Network VM.Config.Options VM.Config.HWType VM.Config.CPU VM.Config.Memory VM.Migrate VM.PowerMgmt Datastore.Audit Datastore.Allocate Pool.Audit Pool.Allocate"
  ["ISOAccess"]="Datastore.Audit Datastore.AllocateTemplate"
  ["LimitedStorageAccess"]="Datastore.Allocate Datastore.AllocateSpace Datastore.Audit"
  ["SDNStudent"]="SDN.Use SDN.Audit"
)
for role in "${!roles[@]}"; do
  if pveum role list | grep -q "$role"; then
    echo "🔄 Mise à jour du rôle $role"
    pveum role modify "$role" -privs "${roles[$role]}"
  else
    echo "✨ Création du rôle $role"
    pveum role add "$role" -privs "${roles[$role]}"
  fi
done

# Crée un rôle TemplateCloner
# Supprime si existant
# pveum role delete TemplateCloner 2>/dev/null
# Crée un rôle qui permet uniquement le clonage et l’accès à la console pour le template
# pveum role add TemplateCloner --privs "VM.Clone"


# === Création utilisateurs, ACL et NAT DNAT ===
echo "🔄 Création des utilisateurs, pools et ACL..."
while IFS=';' read -r USER PASS PORT1 PORT2 PORT3; do
  [[ -z "$USER" || -z "$PASS" ]] && continue

  echo "----------------------------------------"
  echo "👤 Création utilisateur : $USER"
  pveum user add "${USER}@pve" --password "$PASS" --comment "Utilisateur VM limité" || echo "ℹ️ Utilisateur $USER déjà existant."

  POOL_NAME="pool_${USER}"
  pvesh get /pools | grep -q "$POOL_NAME" || pvesh create /pools -poolid "$POOL_NAME" -comment "Ressources de $USER"



	TEMPLATE_SOURCE=100
	TEMPLATE_NAME="template-${USER}"

	# Chercher un VM existant portant ce nom
	EXISTING_TEMPLATE_ID=$(pvesh get /cluster/resources --type vm | grep -w $TEMPLATE_NAME)
	if [[ -n "$EXISTING_TEMPLATE_ID" ]]; then
		echo "⚠️  Le template $TEMPLATE_NAME existe déjà → VMID $EXISTING_TEMPLATE_ID"
		echo "➡️  Ajout au pool si besoin..."

		# Ajout au pool (sans erreur si déjà dedans)
		#pvesh set /pools/$POOL_NAME -vms $EXISTING_TEMPLATE_ID --allow-move true

		echo "✅ Template déjà présent, rien cloné."
	else
    	# Sinon, créer un nouveau template
	   NEW_TEMPLATE_ID=$(pvesh get /cluster/nextid)
	   echo "📦 Création du template privé pour $USER → VMID $NEW_TEMPLATE_ID"
       if ! qm clone $TEMPLATE_SOURCE $NEW_TEMPLATE_ID --name "$TEMPLATE_NAME"; then
	     	echo "❌ Impossible de cloner le template pour $USER."
	   fi
	   # Convertir en template
	   qm template $NEW_TEMPLATE_ID
	   # Ajouter au pool (+ autoriser déplacement si VMID déjà dans un autre pool)
	   pvesh set /pools/$POOL_NAME -vms $NEW_TEMPLATE_ID --allow-move true
	   echo "✅ Template privé assigné à $USER (VMID $NEW_TEMPLATE_ID)"
    fi
	
	

  echo "🛠️ Attribution des ACL pour ${USER}@pve ..."
  pveum acl modify /pool/$POOL_NAME -user ${USER}@pve -role LimitedVMAdmin
  pveum acl modify /pool/$POOL_NAME -user ${USER}@pve -role PVEAuditor
  pveum acl modify /nodes/$NODE -user ${USER}@pve -role LimitedVMAdmin
  pveum acl modify /storage/local -user ${USER}@pve -role ISOAccess
  pveum acl modify /storage/local-lvm -user ${USER}@pve -role LimitedStorageAccess
  pveum acl modify / -user ${USER}@pve -role SDNStudent
  echo "✅ ACL configurées pour ${USER}@pve (pool : $POOL_NAME)"
  
  # ===== Droits pour voir et cloner tous les templates =====
  #pveum user modify ${USER}@pve --group "$GROUP_TEMPLATES"
  # Appliquer TemplateCloner sur chaque template existant
  #for VMID in $(pvesh get /cluster/resources --type vm | jq -r '.[] | select(.template==1) | .vmid'); do
  #  pveum acl modify /vms/$VMID --group "$GROUP_TEMPLATES" --role TemplateCloner
  #done

  echo "✅ Droits templates appliqués pour ${USER}@pve"


done < "$USERFILE"

#DNAT 
echo "🌐 ---------------DNAT------------------"
pats=("22 22" "80 80" "9000 90" "9100 91")
for i in $(seq "$VM_NET_START" "$VM_NET_STOP"); do
    IP_VM="192.168.100.$i"
	for pat in "${pats[@]}"; do
		set -- $pat      # transforme "22 22" → $1=22 $2=22
		port_vm=$1
		port_px=$(( $2 + i * 100 ))
		echo "🌐 DNAT EXTERNAL_IF=$EXTERNAL_IF  VM $PROXMOX_IP:$port_px -> $IP_VM:$port_vm"
		if ! nft list table ip proxmox_nat | grep -q "tcp dport $port_px "; then
			nft add rule ip proxmox_nat prerouting iifname "$EXTERNAL_IF" tcp dport $port_px dnat to $IP_VM:$port_vm
		    echo "✅ DNAT ajouté pour port $port_px"
		else
			echo "ℹ️ DNAT déjà présent pour port $port_px"
		fi	
	done
  done

# Recharge des règles sans écraser la configuration statique
# nft -f /etc/nftables.conf

# systemctl restart nftables

echo "🎉 Création utilisateurs, ACL, NAT IPv4, DHCP et SDN terminée !"
