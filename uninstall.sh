#!/bin/bash

delete_services(){
    # Stop then disable the services before removing anything they depend on.
    echo "[+] Stopping SpyGuard services"
    systemctl stop spyguard-frontend &> /dev/null
    systemctl stop spyguard-backend &> /dev/null
    systemctl stop spyguard-watchers &> /dev/null

    echo "[+] Deleting SpyGuard services"
    systemctl disable spyguard-frontend &> /dev/null
    systemctl disable spyguard-backend &> /dev/null
    systemctl disable spyguard-watchers &> /dev/null

    rm -f /lib/systemd/system/spyguard-frontend.service
    rm -f /lib/systemd/system/spyguard-backend.service
    rm -f /lib/systemd/system/spyguard-watchers.service
    systemctl daemon-reload
}

delete_folder(){
    echo "[+] Deleting SpyGuard folders"
    rm -rf /usr/share/spyguard/
}

delete_packages(){
    pkgs=("tshark"
          "dnsutils"
          "suricata"
          "sqlite3")

    rm -rf /var/log/suricata
    for pkg in "${pkgs[@]}"
    do
        apt -y remove "$pkg" && apt -y purge "$pkg"
    done
    apt autoremove -y &> /dev/null
}

update_hostname(){
   echo -n "[?] Please provide a new hostname: "
   read -r hostname

   echo "$hostname" > /etc/hostname

   # Undo the targeted 127.0.1.1 rewrite done by install.sh (revert to the new hostname).
   if grep -qE '^[[:space:]]*127\.0\.1\.1[[:space:]]+' /etc/hosts; then
     sed -i -E "s/^[[:space:]]*127\.0\.1\.1[[:space:]]+.*/127.0.1.1\t$hostname/" /etc/hosts
   fi

   # Remove the spyguard.local entry added by install.sh.
   sed -i -E '/^[[:space:]]*127\.0\.0\.1[[:space:]]+spyguard\.local([[:space:]]|$)/d' /etc/hosts
}

reboot_box() {
    echo -e "\e[92m[+] SpyGuard uninstalled, let's reboot.\e[39m"
    sleep 5
    reboot
}

# Checking rights.
if [[ $EUID -ne 0 ]]; then
    echo "The update must be run as root. Type in 'sudo bash $0' to run it as root."
	exit 1
else
    delete_services
    delete_folder
    update_hostname
    delete_packages
    reboot_box
fi
