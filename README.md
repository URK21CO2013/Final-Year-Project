# SDN Setup (Open vSwitch + OpenDaylight + Flow Rules)
# Install Open vSwitch (OVS)
sudo apt update
sudo apt install openvswitch-switch

# Create an OVS Bridge
sudo ovs-vsctl add-br br0

sudo ovs-vsctl add-br br1

# Add Ports to the Bridge
sudo ip tuntap add mode tap tap0

sudo ip tuntap add mode tap tap1

sudo ip tuntap add mode tap tap2

sudo ip tuntap add mode tap tap3

sudo ip tuntap add mode tap tap4

sudo ip tuntap add mode tap tap5

sudo ip tuntap add mode tap tap6

sudo ip tuntap add mode tap tap7

# Set the interfaces up
sudo ip link set tap0 up

sudo ip link set tap1 up

sudo ip link set tap2 up

sudo ip link set tap3 up

sudo ip link set tap4 up

sudo ip link set tap5 up

sudo ip link set tap6 up

sudo ip link set tap7 up

# Add the devices to bridges
sudo ovs-vsctl add-port br0 tap0

sudo ovs-vsctl add-port br0 tap1

sudo ovs-vsctl add-port br0 tap2

sudo ovs-vsctl add-port br0 tap3

sudo ovs-vsctl add-port br1 tap4

sudo ovs-vsctl add-port br1 tap5

sudo ovs-vsctl add-port br1 tap6

sudo ovs-vsctl add-port br1 tap7

# Connect OVS to OpenDaylight Controller
sudo ovs-vsctl set-controller br0 tcp:127.0.0.1:6653

sudo ovs-vsctl set-controller br1 tcp:127.0.0.1:6653

# Install OpenDaylight (Silicon Release)
# Download OpenDaylight Silicon
wget https://nexus.opendaylight.org/content/repositories/opendaylight-release/org/opendaylight/integration/distribution-karaf/0.14.0/distribution-karaf-0.14.0.tar.gz

# Extract it
tar -xvzf distribution-karaf-0.14.0.tar.gz

cd distribution-karaf-0.14.0

# Start OpenDaylight
./bin/karaf

# Inside karaf
feature:install odl-l2switch-switch odl-openflowplugin-flow-services-ui

# Install and Configure Flow Rules Manually (Static Microsegmentation)
# Example Flow rules
# Allow communication between tap0 and tap1
sudo ovs-ofctl add-flow br0 "priority=1000,in_port=1,dl_dst=<tap1_mac>,actions=output:2"

sudo ovs-ofctl add-flow br0 "priority=1000,in_port=2,dl_dst=<tap0_mac>,actions=output:1"

# Deny tap5 to tap7
sudo ovs-ofctl add-flow br0 "priority=1000,in_port=6,dl_dst=<tap7_mac>,actions=drop"

# Samba Active Directory Setup (for SDP_INTERNAL domain)
# Install Samba AD Packages
sudo apt update

sudo apt install samba krb5-config krb5-user winbind smbclient

[Realm: SDP.INTERNAL

Domain: SDP

KDC: 127.0.0.1]

# Provision Samba as an AD Domain Controller
sudo samba-tool domain provision --use-rfc2307 --interactive

[Realm: SDP.INTERNAL

Domain: SDP

DNS Backend: SAMBA_INTERNAL

Password_admin12]

# Start and Enable Samba
sudo systemctl stop smbd nmbd winbind

sudo systemctl unmask samba-ad-dc

sudo systemctl enable samba-ad-dc

sudo systemctl start samba-ad-dc

# Create Groups in Samba AD
sudo samba-tool group add admin_group

sudo samba-tool group add user_group

sudo samba-tool group add guest_group

# Add Users to Groups
# Add tap0 and tap1 to admin_group
sudo samba-tool group addmembers admin_group tap0

sudo samba-tool group addmembers admin_group tap4

# Add tap2, tap3, tap4 to user_group
sudo samba-tool group addmembers user_group tap1

sudo samba-tool group addmembers user_group tap2

sudo samba-tool group addmembers user_group tap3

sudo samba-tool group addmembers user_group tap5

sudo samba-tool group addmembers user_group tap6

# tap7 to guest_group
sudo samba-tool group addmembers guest_group tap7

# Database Configuration: MariaDB
Step 1: Install MariaDB

sudo apt update

sudo apt install mariadb-server

sudo systemctl start mariadb

sudo systemctl enable mariadb

Step 2: Create Database and Tables
# Log into MariaDB

sudo mysql -u root -p

# Create and use the database
CREATE DATABASE sdp_database_new;

USE sdp_database_new;

[Connect database to sdp + samba AD for real-time user login updates using the Authentication script]
