# CIS Ubuntu Linux 20.04 LTS Benchmarks v1.1.0 - Level 1

# CIS 1.1.1.1
(
    if find /lib/modules -name 'cramfs*' -print | grep -q 'cramfs' ; then
        [ "$(modprobe -n -v cramfs | grep -E '(cramfs|install)')" = "install /bin/true " ] && \
        [ ! "$(lsmod | grep cramfs)" ]
    fi
) ; report "1.1.1.1" "Ensure mounting of cramfs filesystem is disabled"

# CIS 1.1.1.2
(
    if find /lib/modules -name 'freevxfs*' -print | grep -q 'freevxfs' ; then
        [ "$(modprobe -n -v freevxfs | grep -E '(freevxfs|install)')" = "install /bin/true " ] && \
        [ ! "$(lsmod | grep freevxfs)" ]
    fi
) ; report "1.1.1.2" "Ensure mounting of freevxfs filesystem is disabled"

# CIS 1.1.1.3
(
    if find /lib/modules -name 'jffs2*' -print | grep -q 'jffs2' ; then
        [ "$(modprobe -n -v jffs2 | grep -E '(jffs2|install)')" = "install /bin/true " ] && \
        [ ! "$(lsmod | grep jffs2)" ]
    fi
) ; report "1.1.1.3" "Ensure mounting of jffs2 filesystem is disabled"

# CIS 1.1.1.4
(
    if find /lib/modules -name 'hfs*' -print | grep -q 'hfs' ; then
        [ "$(modprobe -n -v hfs | grep -E '(hfs|install)')" = "install /bin/true " ] && \
        [ ! "$(lsmod | grep hfs)" ]
    fi
) ; report "1.1.1.4" "Ensure mounting of hfs filesystem is disabled"

# CIS 1.1.1.5
(
    if find /lib/modules -name 'hfsplus*' -print | grep -q 'hfsplus' ; then
        [ "$(modprobe -n -v hfsplus | grep -E '(hfsplus|install)')" = "install /bin/true " ] && \
        [ ! "$(lsmod | grep hfsplus)" ]
    fi
) ; report "1.1.1.5" "Ensure mounting of hfsplus filesystem is disabled"

# CIS 1.1.1.6 - Manual

# CIS 1.1.1.7
(
    if find /lib/modules -name 'udf*' -print | grep -q 'udf' ; then
        [ "$(modprobe -n -v udf | grep -E '(udf|install)')" = "install /bin/true " ] && \
        [ ! "$(lsmod | grep udf)" ]
    fi
) ; report "1.1.1.7" "Ensure mounting of udf filesystems is disabled" 

# CIS 1.1.2
(
    findmnt -n /tmp | grep -Eq '^/tmp\s+tmpfs'
) ; report "1.1.2" "Ensure /tmp is configured"

# CIS 1.1.3
(
    findmnt -n /tmp | grep -q 'nodev'
) ; report "1.1.3" "Ensure nodev option set on /tmp partition"

# CIS 1.1.4
(
    findmnt -n /tmp | grep -q 'nosuid'
) ; report "1.1.4" "Ensure nosuid option set on /tmp partition"

# CIS 1.1.5
(
    findmnt -n /tmp | grep -q 'noexec'
) ; report "1.1.5" "Ensure noexec option set /tmp partition"

# CIS 1.1.6
(
    findmnt -n /dev/shm | grep -Eq '^/dev/shm\s+tmpfs'
) ; report "1.1.6" "Ensure /dev/shm is configured"

# CIS 1.1.7
(
    findmnt -n /dev/shm | grep -q 'nodev'
) ; report "1.1.7" "Ensure nodev option set on /dev/shm partition"

# CIS 1.1.8
(
    findmnt -n /dev/shm | grep -q 'nosuid'
) ; report "1.1.8" "Ensure nosuid option set on /dev/shm partition"

# CIS 1.1.9
(
    findmnt -n /dev/shm | grep -q 'noexec'
) ; report "1.1.9" "Ensure noexec option set on /dev/shm partition"

# CIS 1.1.10
(
    findmnt -n /var | grep -Eq '^/var\s+'
) ; report "1.1.10" "Ensure separate partition exists for /var" "Level 2"

# CIS 1.1.11
(
    findmnt -n /var/tmp | grep -Eq '^/var/tmp\s+'
) ; report "1.1.11" "Ensure separate partition exists for /var/tmp" "Level 2"

# CIS 1.1.12
(
    [ ! "$(findmnt -n /var/tmp | grep -v 'nodev')" ]
) ; report "1.1.12" "Ensure /var/tmp partition includes the nodev option"

# CIS 1.1.13
(
    [ ! "$(findmnt -n /var/tmp | grep -v 'nosuid')" ]
) ; report "1.1.13" "Ensure /var/tmp partition includes the nosuid option"

# CIS 1.1.14
(
    [ ! "$(findmnt -n /var/tmp | grep -v 'noexec')" ]
) ; report "1.1.14" "Ensure /var/tmp partition includes the noexec option"

# CIS 1.1.15
(
    findmnt -n /var/log | grep -Eq '^/var/log\s+'
) ; report "1.1.15" "Ensure separate partition exists for /var/log" "Level 2"

# CIS 1.1.16
(
    findmnt -n /var/log/audit | grep -Eq '^/var/log/audit\s+'
) ; report "1.1.16" "Ensure separate partition exists /var/log/audit" "Level 2"

# CIS 1.1.17
(
    findmnt -n /home | grep -Eq '^/home\s+'
) ; report "1.1.17" "Ensure separate partition exists for /home" "Level 2"

# CIS 1.1.18
(
    [ ! "$(findmnt -n /home | grep -v 'nodev')" ]
) ; report "1.1.18" "Ensure /home partition includes the nodev option"

# CIS 1.1.19 - Manual

# CIS 1.1.20 - Manual

# CIS 1.1.21 - Manual

# CIS 1.1.22
(
    [ ! "$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null)" ]
) ; report "1.1.22" "Ensure sticky bit is set on all world-writable directories"

# CIS 1.1.23
(
    [ "$(systemctl is-enabled autofs 2> /dev/null)" != "enabled" ] && \
    [ ! "$(dpkg -s autofs 2> /dev/null)" ]
) ; report "1.1.23" "Disable Automounting"

# CIS 1.1.24
(
    if find /lib/modules -name 'usb-storage*' -print | grep -q 'usb-storage' ; then
        [ "$(modprobe -n -v usb-storage)" = "install /bin/true " ] && \
        [ ! "$(lsmod | grep usb-storage)" ]
    fi
) ; report "1.1.24" "Disable USB Storage"

# CIS 1.2.1 - Manual

# CIS 1.2.2 - Manual

# CIS 1.3.1
(
    dpkg -s aide &> /dev/null && \
    dpkg -s aide-common &> /dev/null
) ; report "1.3.1" "Ensure AIDE is installed"

# CIS 1.3.2
(
    grep -Ersq '^([^#]+\s+)?(\/usr\/s?ban\/|^\s*)aide(\.wrapper)?\s(--check|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/
) ; report "1.3.2" "Ensure filesystem integrity is regularly checked"

# 1.4.1
(
    grep -Eq '^\s*chmod\s+400\s+\$\{grub_cfg\}\.new\s+||\s+true$' /usr/sbin/grub-mkconfig && \
    [ "$(grep -E '^\s*chmod\s+[0-7][0-7][0-7]\s+\$\{grub_cfg\}\.new' -B1 /usr/sbin/grub-mkconfig | head -1)" = "if [ \"x\${grub_cfg}\" != \"x\" ]; then" ]
) ; report "1.4.1" "Ensure permissions on bootloader config are not overridden"

# 1.4.2
(
    grep -q '^set superusers=".*"' /boot/grub/grub.cfg && \
    grep -Eq '^password_pbkdf2\s.*\s.*$' /boot/grub/grub.cfg
) ; report "1.4.2" "Ensure bootloader password is set"

# 1.4.3
(
    stat --format='%a %u/%U %g/%G' /boot/grub/grub.cfg | grep -q '400 0/root 0/root'
) ; report "1.4.3" "Ensure permissions on bootloader config are configured"

# 1.4.4
(
    ! grep -Eq '^root:\$[0-9]' /etc/shadow
) ; report "1.4.4" "Ensure authentication required for single user mode"

# 1.5.1
(
    journalctl | grep 'protection: active' &> /dev/null
) ; report "1.5.1" "Ensure XD/NX support is enabled"

# 1.5.2
(
    sysctl kernel.randomize_va_space | grep -Eq '^kernel\.randomize_va_space\s=\s2$' && \
    grep -Eq '^\s*kernel\.randomize_va_space\s*=\s*2\s*$' /etc/sysctl.conf /etc/sysctl.d/*
) ; report "1.5.2" "Ensure address space layout randomization (ASLR) is enabled"

# 1.5.3
(
    ! dpkg -s prelink &> /dev/null
) ; report "1.5.3" "Ensure prelink is not installed"

# 1.5.4
(
    grep -Esh '^(\*|\s).*hard.*core.*(\s+#.*)?$' /etc/security/limits.conf /etc/security/limits.d/* | grep -q '\*\s*hard\s*core\s*0' && \
    sysctl fs.suid_dumpable | grep -Eq '^fs\.suid_dumpable\s=\s0' && \
    grep -Eshq '^fs\.suid_dumpable\s?=\s?0$' /etc/sysctl.conf /etc/sysctl.d/*
) ; report "1.5.4" "Ensure core dumps are restricted"

# 1.6.1.1
(
    dpkg -s apparmor &> /dev/null
) ; report "1.6.1.1" "Ensure AppArmor is installed"

# 1.6.1.2
(
    [ ! "$(grep '^\s*linux' /boot/grub/grub.cfg | grep -v 'apparmor=1')" ] && \
    [ ! "$(grep '^\s*linux' /boot/grub/grub.cfg | grep -v 'security=apparmor')" ]
) ; report "1.6.1.2" "Ensure AppArmor is enabled in the bootloader configuration"

# 1.6.1.3
(
    loaded=$(apparmor_status | grep profiles | grep 'profiles are loaded' | awk '{print $1}')
    enforce=$(apparmor_status | grep profiles | grep 'profiles are in enforce mode' | awk '{print $1}')
    complain=$(apparmor_status | grep profiles | grep 'profiles are in complain mode' | awk '{print $1}')
    [ "$(expr $enforce + $complain)" = "$loaded" ] && \
    [ "$(apparmor_status | grep processes | grep 'processes are unconfined but have a profile defined' | awk '{print $1}')" = "0" ]

    exit $?
) ; report "1.6.1.3" "Ensure all AppArmor Profiles are in enforce or complain mode"

# CIS 1.6.1.4
(
    [ "$(apparmor_status | grep profiles | grep 'profiles are loaded' | awk '{print $1}')" = "$(apparmor_status | grep profiles | grep 'profiles are in enforce mode' | awk '{print $1}')" ] && \
    [ "$(apparmor_status | grep profiles | grep 'profiles are in complain mode' | awk '{print $1}')" = "0" ] && \
    [ "$(apparmor_status | grep processes | grep 'processes are unconfined but have a profile defined' | awk '{print $1}')" = "0" ]
) ; report "1.6.1.4" "Ensure all AppArmor Profiles are enforcing" "Level 2"

# CIS 1.7.1
(
    [ ! "$(grep -Eis '(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/motd)" ]
) ; report "1.7.1" "Ensure message of the day is configured properly"

# CIS 1.7.2
(
    [ ! "$(grep -Ei '(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/issue)" ]
) ; report "1.7.2" "Ensure local login warning banner is configured properly"

# CIS 1.7.3
(
    [ ! "$(grep -Ei '(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/issue.net)" ]
) ; report "1.7.3" "Ensure remote login warning banner is configured properly"

# CIS 1.7.4
(
    if [ -f /etc/motd ]; then 
        stat --format='%a %u/%U %g/%G' /etc/motd | grep -q '644 0/root 0/root'
    fi
) ; report "1.7.4" "Ensure permissions on /etc/motd are configured"

# CIS 1.7.5
(
    stat --format='%a %u/%U %g/%G' /etc/issue | grep -q '644 0/root 0/root'
) ; report "1.7.5" "Ensure permissions on /etc/issue are configured"

# CIS 1.7.6
(
    stat --format='%a %u/%U %g/%G' /etc/issue.net | grep -q '644 0/root 0/root'
) ; report "1.7.6" "Ensure permissions on /etc/issue.net are configured"

# CIS 1.8.1 - Manual

# CIS 1.8.2
(
    if dpkg -s gdm3 &> /dev/null ; then
        grep -q 'banner-message-enable=true' /etc/gdm3/greeter.dconf-defaults && \
        grep -q 'banner-message-text=' /etc/gdm3/greeter.dconf-defaults && \
        grep -q 'disable-user-list=true' /etc/gdm3/greeter.dconf-defaults
    fi
) ; report "1.8.2" "Ensure GCM login banner is configured"

# CIS 1.8.3
(
    if dpkg -s gdm3 &> /dev/null ; then
        grep -Eq '^\s*disable-user-list\s*=\s*true\b' /etc/gdm3/greeter.dconf-defaults
    fi
) ; report "1.8.3" "Ensure disable-user-list is enabled"

# CIS 1.8.4
(
    if dpkg -s gdm3 &> /dev/null ; then
        [ ! "$(grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm3/custom.conf)" ]
    fi
) ; report "1.8.4" "Ensure XDCMP is not enabled"

# CIS 1.9 - Manual

# CIS 2.1.1.1
(
    timesyncd_used="$(systemctl is-enabled systemd-timesyncd &> /dev/null && echo 1 || echo 0)"
    chrony_used="$(dpkg -s chrony &> /dev/null && echo 1 || echo 0)"
    ntp_used="$(dpkg -s ntp &> /dev/null && echo 1 || echo 0)"
    
    [ "$(expr $timesyncd_used + $chrony_used + $ntp_used)" = "1" ]
    exit $?
) ; report "2.1.1.1" "Ensure time synchronization is in use"

# CIS 2.1.1.2
(
    if ! dpkg -s chrony &> /dev/null && ! dpkg -s ntp &> /dev/null ; then
        systemctl is-enabled systemd-timesyncd.service &> /dev/null && \
        timedatectl status | grep -Eq '^\s*NTP enabled:\s*yes' && \
        timedatectl status | grep -Eq '^\s*NTP synchronized:\s*yes'
    fi
) ; report "2.1.1.2" "Ensure systemd-timesyncd is configured"

# CIS 2.1.1.3
(
    if ! dpkg -s ntp &> /dev/null && ! systemctl is-enabled systemd-timesyncd &> /dev/null ; then
        grep -Eq '^(server|pool)' /etc/chrony/chrony.conf && \
        [ ! "$(ps -ef | grep chronyd | grep -v 'grep' | awk '{print $1}' | grep -v '_chrony')" ]
    fi
) ; report "2.1.1.3" "Ensure chrony is configured"

# CIS 2.1.1.4
(
    if ! systemctl is-enabled systemd-timesyncd &> /dev/null && ! dpkg -s chrony &> /dev/null ; then
        grep -Eq '^restrict\s*(-[46])?\s*default( kod| nomodify| notrap| nopeer| noquery){5}' /etc/ntp.conf && \
        grep -Eq '^(server|pool)' /etc/ntp.conf && \
        grep -q 'RUNASUSER=ntp' /etc/init.d/ntp
    fi
) ; report "2.1.1.4" "Ensure ntp is configured"

# CIS 2.1.2
(
    ! dpkg -l xserver-xorg* &> /dev/null
) ; report "2.1.2" "Ensure X Window System is not installed"

# CIS 2.1.3
(
    ! dpkg -s avahi-daemon &> /dev/null
) ; report "2.1.3" "Ensure Avahi Server is not installed"

# CIS 2.1.4
(
    ! dpkg -s cups &> /dev/null
) ; report "2.1.4" "Ensure CUPS is not installed"

# CIS 2.1.5
(
    ! dpkg -s isc-dhcp-server &> /dev/null
) ; report "2.1.5" "Ensure DHCP Server is not installed"

# CIS 2.1.6
(
    ! dpkg -s slapd &> /dev/null
) ; report "2.1.6" "Ensure LDAP server is not installed"

# CIS 2.1.7
(
    ! dpkg -s nfs-kernel-server &> /dev/null
) ; report "2.1.7" "Ensure NFS is not installed"

# CIS 2.1.8
(
    ! dpkg -s bind9 &> /dev/null
) ; report "2.1.8" "Ensure DNS Server is not installed"

# CIS 2.1.9
(
    ! dpkg -s vsftpd &> /dev/null
) ; report "2.1.9" "Ensure FTP Server is not installed"

# CIS 2.1.10
(
    ! dpkg -s apache2 &> /dev/null
) ; report "2.1.10" "Ensure HTTP server is not installed"

# CIS 2.1.11
(
    ! dpkg -s dovecot-imapd &> /dev/null && \
    ! dpkg -s dovecot-pop3d &> /dev/null
) ; report "2.1.11" "Ensure IMAP and POP3 server are not installed"

# CIS 2.1.12
(
    ! dpkg -s samba &> /dev/null
) ; report "2.1.12" "Ensure Samba is not installed"

# CIS 2.1.13
(
    ! dpkg -s squid &> /dev/null
) ; report "2.1.13" "Ensure HTTP Proxy Server is not installed"

# CIS 2.1.14
(
    ! dpkg -s snmpd &> /dev/null
) ; report "2.1.14" "Ensure SNMP Server is not installed"

# CIS 2.1.15
(
    ss -lntu | grep -E ':25\s' | grep -Eq '\s(127.0.0.1|\[?::1\]?):25\s'
) ; report "2.1.15" "Ensure mail transfer agent is configured for local-only mode"

# CIS 2.1.16
(
    ! dpkg -s rsync &> /dev/null
) ; report "2.1.16" "Ensure rsync service is not installed"

# CIS 2.1.17
(
    ! dpkg -s nis &> /dev/null
) ; report "2.1.17" "Ensure NIS Server is not installed"

# CIS 2.2.1
(
    ! dpkg -s nis &> /dev/null
) ; report "2.2.1" "Ensure NIS Client is not installed"

# CIS 2.2.2
(
    ! dpkg -s rsh-client &> /dev/null
) ; report "2.2.2" "Ensure rsh client is not installed"

# CIS 2.2.3
(
    ! dpkg -s talk &> /dev/null
) ; report "2.2.3" "Ensure talk client is not installed"

# CIS 2.2.4
(
    ! dpkg -s telnet &> /dev/null
) ; report "2.2.4" "Ensure telnet client is not installed"

# CIS 2.2.5
(
    ! dpkg -s ldap-utils &> /dev/null
) ; report "2.2.5" "Ensure LDAP client is not installed"

# CIS 2.2.6
(
    ! dpkg -s rpcbind &> /dev/null
) ; report "2.2.6" "Ensure RPC is not installed"

# CIS 2.3 - Manual

# CIS 3.1.1 - Manual

# CIS 3.1.2
(
    success=true
    if command -v nmcli &> /dev/null ; then
        nmcli radio all | grep -Eq '\s*\S+\s+disabled\s+\S+\s+disabled\b' || success=false
    elif [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
        mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
        for dm in $mname; do
            grep -Eq "^\s*install\s+$dm\s+/bin/(true|false)" /etc/modprobe.d/*.conf || success=false
        done
    fi

    [ "$success" = "true" ]
    exit $?
) ; report "3.1.2" "Ensure wireless interfaces are disabled"

# CIS 3.2.1
(
    sysctl net.ipv4.conf.all.send_redirects | grep -Eq '^net\.ipv4\.conf\.all\.send_redirects\s*=\s*0$' && \
    sysctl net.ipv4.conf.default.send_redirects | grep -Eq '^net\.ipv4\.conf\.default\.send_redirects\s*=\s*0$' && \
    grep -Eqs '^\s*net\.ipv4\.conf\.all\.send_redirects\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf && \
    grep -Eqs '^\s*net\.ipv4\.conf\.default\.send_redirects\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf
) ; report "3.2.1" "Ensure packet redirect sending is disabled"

# CIS 3.2.2
(
    sysctl net.ipv4.ip_forward | grep -Eq '^net\.ipv4\.ip_forward\s*=\s*0$' && \
    grep -Eqs '^\s*net\.ipv4\.ip_forward\s*=\s*0$' /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf && \

    if [ -f /proc/net/if_inet6 ] ; then
        sysctl net.ipv6.conf.all.forwarding | grep -Eq '^net\.ipv6\.conf\.all\.forwarding\s*=\s*0$' && \
        grep -Eqs '^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*0$' /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/systcl.d/*.conf /run/sysctl.d/*.conf
    fi
) ; report "3.2.2" "Ensure IP forwarding is disabled"

# CIS 3.3.1
(
    sysctl net.ipv4.conf.all.accept_source_route | grep -Eq '^net\.ipv4\.conf\.all\.accept_source_route\s*=\s*0$' && \
    sysctl net.ipv4.conf.default.accept_source_route | grep -Eq '^net\.ipv4\.conf\.default\.accept_source_route\s*=\s*0$' && \
    grep -Eqs '^\s*net\.ipv4\.conf\.all\.accept_source_route\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf && \
    grep -Eqs '^\s*net\.ipv4\.conf\.default\.accept_source_route\s*=0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf && \

    if [ -f /proc/net/if_inet6 ] ; then
        sysctl net.ipv6.conf.all.accept_source_route | grep -Eq '^net\.ipv6\.conf\.all\.accept_source_route\s*=\s*0$' && \
        sysctl net.ipv6.conf.default.accept_source_route | grep -Eq '^net\.ipv6\.conf\.default\.accept_source_route\s*=\s*0$' && \
        grep -Eqs '^\s*net\.ipv6\.conf\.all\.accept_source_route\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf && \
        grep -Eqs '^\s*net\.ipv6\.conf\.default\.accept_source_route\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf
    fi
) ; report "3.3.1" "Ensure source routed packets are not accepted"

# CIS 3.3.2
(
    sysctl net.ipv4.conf.all.accept_redirects | grep -Eq '^net\.ipv4\.conf\.all\.accept_redirects\s*=\s*0$' && \
    sysctl net.ipv4.conf.default.accept_redirects | grep -Eq '^net\.ipv4\.conf\.default\.accept_redirects\s*=\s*0$' && \
    grep -Eqs '^\s*net\.ipv4\.conf\.all\.accept_redirects\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf && \
    grep -Eqs '^\S*net\.ipv4\.conf\.default\.accept_redirects\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf && \

    if [ -f /proc/net/if_inet6 ] ; then
        sysctl net.ipv6.conf.all.accept_redirects | grep -Eq '^net\.ipv6\.conf\.all\.accept_redirects\s*=\s*0$' && \
        sysctl net.ipv6.conf.default.accept_redirects | grep -Eq '^net\.ipv6\.conf\.default\.accept_redirects\s*=\s*0$' && \
        grep -Eqs '^\s*net\.ipv6\.conf\.all\.accept_redirects\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf && \
        grep -Eqs '^\s*net\.ipv6\.conf\.default\.accept_redirects\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf
    fi
) ; report "3.3.2" "Ensure ICMP redirects are not accepted"

# CIS 3.3.3
(
    sysctl net.ipv4.conf.all.secure_redirects | grep -Eq '^net\.ipv4\.conf\.all\.secure_redirects\s*=\s*0$' && \
    sysctl net.ipv4.conf.default.secure_redirects | grep -Eq '^net\.ipv4\.conf\.default\.secure_redirects\s*=\s*0$' && \
    grep -Eqs '^\s*net\.ipv4\.conf\.all\.secure_redirects\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf && \
    grep -Eqs '^\s*net\.ipv4\.conf\.default\.secure_redirects\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf
) ; report "3.3.3" "Ensure secure ICMP redirects are not accepted"

# CIS 3.3.4
(
    sysctl net.ipv4.conf.all.log_martians | grep -Eq '^net\.ipv4\.conf\.all\.log_martians\s*=\s*1$' && \
    sysctl net.ipv4.conf.default.log_martians | grep -Eq '^net\.ipv4\.conf\.default\.log_martians\s*=\s*1$' && \
    grep -Eqs '^\s*net\.ipv4\.conf\.all\.log_martians\s*=\s*1\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf && \
    grep -Eqs '^\s*net\.ipv4\.conf\.default\.log_martians\s*=\s*1\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf
) ; report "3.3.4" "Ensure suspicious packets are logged"

# CIS 3.3.5
(
    sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep -Eq '^net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*1$' && \
    grep -Eqs '^\s*net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*1\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf
) ; report "3.3.5" "Ensure broadcast ICMP requests are ignored"

# CIS 3.3.6
(
    sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep -Eq '^net\.ipv4\.icmp_ignore_bogus_error_responses\s*=\s*1$' && \
    grep -Eqs '^\s*net\.ipv4\.icmp_ignore_bogus_error_responses\s*=\s*1\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf
) ; report "3.3.6" "Ensure bogus ICMP responses are ignored"

# CIS 3.3.7
(
    sysctl net.ipv4.conf.all.rp_filter | grep -Eq '^net\.ipv4\.conf\.all\.rp_filter\s*=\s*1$' && \
    sysctl net.ipv4.conf.default.rp_filter | grep -Eq '^net\.ipv4\.conf\.default\.rp_filter\s*=\s*1$' && \
    grep -Eqs '^\s*net\.ipv4\.conf\.all\.rp_filter\s*=\s*1\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf && \
    grep -Eqs '^\s*net\.ipv4\.conf\.default\.rp_filter\s*=\s*1\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf
) ; report "3.3.7" "Ensure Reverse Path Filtering is enabled"

# CIS 3.3.8
(
    sysctl net.ipv4.tcp_syncookies | grep -Eq '^net\.ipv4\.tcp_syncookies\s*=\s*1$' && \
    grep -Eqs '^\s*net\.ipv4\.tcp_syncookies\s*=\s*1\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf
) ; report "3.3.8" "Ensure TCP SYN Cookies is enabled"

# CIS 3.3.9
(
    if [ -f /proc/net/if_inet6 ]; then
        sysctl net.ipv6.conf.all.accept_ra | grep -Eq '^net\.ipv6\.conf\.all\.accept_ra\s*=\s*0$' && \
        sysctl net.ipv6.conf.default.accept_ra | grep -Eq '^net\.ipv6\.conf\.default\.accept_ra\s*=\s*0$' && \
        grep -Eqs '^\s*net\.ipv6\.conf\.all.accept_ra\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf && \
        grep -Eqs '^\s*net\.ipv6\.conf\.default.accept_ra\s*=\s*0\s*$' /etc/sysctl.conf /etc/sysctl.d/*.conf
    fi
) ; report "3.3.9" "Ensure IPv6 router advertisements are not accepted"

# CIS 3.4.1
(
    if find /lib/modules -name 'dccp*' -print | grep -q 'dccp' ; then
        [ "$(modprobe -n -v dccp | grep -E '(dccp|install)')" = "install /bin/true " ] && \
        [ ! "$(lsmod | grep dccp)" ]
    fi    
) ; report "3.4.1" "Ensure DCCP is disabled" "Level 2"

# CIS 3.4.2
(
    if find /lib/modules -name 'sctp*' -print | grep -q 'sctp' ; then
        [ "$(modprobe -n -v sctp | grep -E '(sctp|install)')" = "install /bin/true " ] && \
        [ ! "$(lsmod | grep sctp)" ]
    fi
) ; report "3.4.2" "Ensure SCTP is disabled" "Level 2"

# CIS 3.4.3
(
    if find /lib/modules -name 'rds*' -print | grep -q 'rds' ; then
        [ "$(modprobe -n -v rds | grep -E '(rds|install)')" = "install /bin/true " ] && \
        [ ! "$(lsmod | grep rds)" ]
    fi
) ; report "3.4.3" "Ensure RDS is disabled" "Level 2"

# CIS 3.4.4
(
    if find /lib/modules -name 'tipc*' -print | grep -q 'tipc' ; then
        [ "$(modprobe -n -v tipc | grep -E '(tipc|install)')" = "install /bin/true " ] && \
        [ ! "$(lsmod | grep tipc)" ]
    fi
) ; report "3.4.4" "Ensure TIPC is disabled" "Level 2"

# CIS 3.5
#   Determine which Firewall utility is used.

ufw_used=$(dpkg -s ufw &> /dev/null && echo 1 || echo 0)
nftables_used=$(dpkg -s nftables &> /dev/null && echo 1 || echo 0)
iptables_used=$(dpkg -s iptables &> /dev/null && dpkg -s iptables-persistent &> /dev/null && echo 1 || echo 0)

# CIS 3.5.1.1
(
    if [ "$ufw_used" = "1" ] ; then
        dpkg -s ufw &> /dev/null
    fi
) ; report "3.5.1.1" "Ensure ufw is installed"

# CIS 3.5.1.2
(
    if [ "$ufw_used" = "1" ] ; then
        ! dpkg -s iptables-persistent &> /dev/null
    fi
) ; report "3.5.1.2" "Ensure iptables-persistent is not installed with ufw"

# CIS 3.5.1.3
(
    if [ "$ufw_used" = "1" ] ; then
        systemctl is-enabled ufw &> /dev/null && \
        ufw status 2> /dev/null | grep -q 'Status: active'
    fi
) ; report "3.5.1.3" "Ensure ufw service is enabled"

# CIS 3.5.1.4
(
    if [ "$ufw_used" = "1" ] ; then
        rule_1="$(ufw status verbose 2> /dev/null | grep -En '^Anywhere on lo\s+ALLOW IN\s+Anywhere' | cut -d: -f1)" && \
        rule_2="$(ufw status verbose 2> /dev/null | grep -En '^Anywhere\s+DENY IN\s+127\.0\.0\.0/8' | cut -d: -f1)" && \
        rule_5="$(ufw status verbose 2> /dev/null | grep -En '^Anywhere\s+ALLOW OUT\s+Anywhere on lo' | cut -d: -f1)" && \
        
        if [ -f /proc/net/if_inet6 ] ; then
            rule_3="$(ufw status verbose 2> /dev/null | grep -En '^Anywhere (v6) on lo\s+ALLOW IN\s+Anywhere (v6)' | cut -d: -f1)" && \
            rule_4="$(ufw status verbose 2> /dev/null | grep -En '^Anywhere (v6)\s+DENY IN\s+::1' | cut -d: -f1)" && \
            rule_6="$(ufw status verbose 2> /dev/null | grep -En '^Anywhere (v6)\s+ALLOW OUT\s+Anywhere (v6) on lo' | cut -d: -f1)" && \

            expr $rule_1 \< $rule_2 \< $rule_3 \< $rule_4 \< $rule_5 \< $rule_6
        else
            expr $rule_1 \< $rule_2 \< $rule_5
        fi
    fi
) ; report "3.5.1.4" "Ensure ufw loopback traffic is configured"

# CIS 3.5.1.5 - Manual

# CIS 3.5.1.6 - Manual

# CIS 3.5.1.7
(
    if [ "$ufw_used" = "1" ] ; then
        ufw status verbose 2> /dev/null | grep -Eq '^Default: (deny|reject) \(incoming\), (deny|reject) \(outgoing\), (deny|reject) \(routed\)'
    fi
) ; report "3.5.1.7" "Ensure ufw default deny firewall policy"

# CIS 3.5.2.1
(
    if [ "$nftables_used" = "1" ] ; then
        dpkg-query -s nftables &> /dev/null
    fi
) ; report "3.5.2.1" "Ensure nftables is installed"

# CIS 3.5.2.2
(
    if [ "$nftables_used" = "1" ] ; then
        ! dpkg-query -s ufw &> /dev/null || \
        ufw status | grep -q '^Status:\s*inactive$'
    fi
) ; report "3.5.2.2" "Ensure ufw is uninstalled or disabled with nftables"

# CIS 3.5.2.3 - Manual

# CIS 3.5.2.4
(
    if [ "$nftables_used" = "1" ] ; then
        nft list tables | grep -Eq '^table\s\w+\s\w+$'
    fi
) ; report "3.5.2.4" "Ensure a nftables table exists"

# CIS 3.5.2.5
(
    if [ "$nftables_used" = "1" ] ; then
        nft list ruleset | grep -E '^\s*type\s+filter\s+hook\s+input\s+priority\s+' &> /dev/null && \
        nft list ruleset | grep -E '^\s*type\s+filter\s+hook\s+forward\s+priority\s+' &> /dev/null && \
        nft list ruleset | grep -E '^\s*type\s+filter\s+hook\s+output\s+priority\s+' &> /dev/null
    fi
) ; report "3.5.2.5" "Ensure nftables base chains exist"

# CIS 3.5.2.6
(
    if [ "$nftables_used" = "1" ] ; then
        nft list ruleset | awk '/hook input/,/}/' | grep -q 'iif "lo" accept' && \
        nft list ruleset | awk '/hook input/,/}/' | grep -q 'ip saddr 127\.0\.0\.0/8 .*' && \

        if [ -f /proc/net/if_inet6 ]; then
            nft list ruleset | awk '/hook input/,/}/' | grep -q 'ip6 saddr ::1 .*'
        fi
    fi
) ; report "3.5.2.6" "Ensure nftables loopback traffic is configured"

# CIS 3.5.2.7 - Manual

# CIS 3.5.2.8
(
    if [ "$nftables_used" = "1" ] ; then
        nft list ruleset | grep 'hook input' | grep -q 'policy drop;' && \
        nft list ruleset | grep 'hook forward' | grep -q 'policy drop;' && \
        nft list ruleset | grep 'hook output' | grep -q 'policy drop;'
    fi
) ; report "3.5.2.8" "Ensure nftables default deny firewall policy"

# CIS 3.5.2.9
(
    if [ "$nftables_used" = "1" ] ; then
        systemctl is-enabled nftables &> /dev/null
    fi
) ; report "3.5.2.9" "Ensure nftables service is enabled"

# CIS 3.5.2.10
(
    if [ "$nftables_used" = "1" ] ; then
        [ -n "$(grep -E '^\s*include' /etc/nftables.conf)" ] && \
        input_hook="$(awk '/hook input/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/nftables.conf))" && \
        forward_hook="$(awk '/hook forward/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/nftables.conf))" && \
        output_hook="$(awk '/hook output/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/nftables.conf))" && \
        echo "$input_hook" | grep -q 'type filter hook input priority 0; policy drop;' && \
        echo "$input_hook" | grep -q 'iif "lo" accept' && \
        echo "$input_hook" | grep -q 'ip saddr 127.0.0.0/8' && \
        echo "$input_hook" | grep -q 'ip protocol tcp ct state established accept' && \
        echo "$input_hook" | grep -q 'ip protocol udp ct state established accept' && \
        echo "$input_hook" | grep -q 'ip protocol icmp ct state established accept' && \
        echo "$input_hook" | grep -q 'tcp dport ssh accept' && \
        echo "$input_hook" | grep -q 'icmp type { destination-unreachable, router-advertisement, router-solicitation, time-exceeded, parameter-problem } accept' && \
        echo "$input_hook" | grep -q 'ip protocol igmp accept' && \
        echo "$forward_hook" | grep -q 'type filter hook forward priority 0; policy drop;' && \
        echo "$output_hook" | grep -q 'type filter hook output priority 0; policy drop;' && \
        echo "$output_hook" | grep -q 'ip protocol tcp ct state established,related,new accept' && \
        echo "$output_hook" | grep -q 'ip protocol udp ct state established,related,new accept' && \
        echo "$output_hook" | grep -q 'ip protocol icmp ct state established,related,new accept' && \
        if [ -f /proc/net/if_inet6 ] ; then
            echo "$input_hook" | grep -q 'icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, mld-listener-query, mld-listener-report, mld-listener-done, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, ind-neighbor-advert, mld2-listener-report } accept'
        fi
    fi
) ; report "3.5.2.10" "Ensure nftables rules are permanent"

# CIS 3.5.3.1.1
(
    if [ "$iptables_used" = "1" ] ; then
        dpkg -s iptables &> /dev/null && \
        dpkg -s iptables-persistent &> /dev/null
    fi
) ; report "3.5.3.1.1" " Ensure iptables packages are installed"

# CIS 3.5.3.1.2
(
    if [ "$iptables_used" = "1" ] ; then
        ! dpkg -s nftables &> /dev/null
    fi
) ; report "3.5.3.1.2" "Ensure nftables is not installed with iptables"

# CIS 3.5.3.1.3
(
    if [ "$iptables_used" = "1" ] ; then
        ! dpkg-query -s ufw &> /dev/null || ufw status | grep -q 'Status: inactive' || ! systemctl is-enabled ufw &> /dev/null
    fi
) ; report "3.5.3.1.3" "Ensure ufw is uninstalled or disabled with iptables"

# CIS 3.5.3.2.1
(
    if [ "$iptables_used" = "1" ]; then
        iptables -L INPUT -v -n | grep -Eq 'ACCEPT\s+all\s+--\s+lo\s+\*\s+0\.0\.0\.0/0\s+0\.0\.0\.0/0' && \
        iptables -L INPUT -v -n | grep -Eq 'DROP\s+all\s+--\s+\*\s+\*\s+127\.0\.0\.0/8\s+0\.0\.0\.0/0' && \
        iptables -L OUTPUT -v -n | grep -Eq 'ACCEPT\s+all\s+--\s+\*\s+lo\s+0\.0\.0\.0/0\s+0\.0\.0\.0/0'
    fi
) ; report "3.5.3.2.1" "Ensure iptables loopback traffic is configured"

# CIS 3.5.3.2.2 - Manual

# CIS 3.5.3.2.3
(
    if [ "$iptables_used" = "1" ] ; then
        iptables -L | grep -q 'Chain INPUT (policy DROP)' && \
        iptables -L | grep -q 'Chain FORWARD (policy DROP)' && \
        iptables -L | grep -q 'Chain OUTPUT (policy DROP)'
    fi
) ; report "3.5.3.2.3" "Ensure iptables default deny firewall policy"

# CIS 3.5.3.2.4
(
    if [ "$iptables_used" = "1" ] ; then
        proto_ports=($(ss -4tuln | tail -n +2 | awk '{print $1 "/" $5}' | grep -v '127\.0\.0\.' | sed -r 's~(.*)/.*:~\1/~'))

        success=true
        for proto_port in ${proto_ports[@]} ; do
            protocol=${proto_port%%/*}
            port=${proto_port##*/}

            iptables -L INPUT -v -n | grep -q "ACCEPT\s+$protocol\s+--\s+\*\s+\*\s+0\.0\.0\.0/0\s+0\.0\.0\.0/0\s+$protocol dpt:$port state NEW" || success=false
        done

        [ "$success" = "true" ]
        exit $?
    fi
) ; report "3.5.3.2.4" "Ensure iptables firewall rules exist for all open ports"

# CIS 3.5.3.3.1
(
    if [ "$iptables_used" = "1" ] && [ -f /proc/net/if_inet6 ] ; then
        ip6tables -L INPUT -v -n | grep -Eq 'ACCEPT\s+all\s+lo\s+\*\s+::/0\s+::/0' && \
        ip6tables -L INPUT -v -n | grep -Eq 'DROP\s+all\s+\*\s+\*\s+::1\s+::/0' && \
        ip6tables -L OUTPUT -v -n | grep -Eq 'ACCEPT\s+all\s+\*\s+lo\s+::/0\s+::/0'
    fi
) ; report "3.5.3.3.1" "Ensure ip6tables loopback traffic is configured"

# CIS 3.5.3.3.2 - Manual

# CIS 3.5.3.3.3
(
    if [ "$iptables_used" = "1" ] && [ -f /proc/net/if_inet6 ] ; then
        ip6tables -L | grep -q 'Chain INPUT (policy DROP)' && \
        ip6tables -L | grep -q 'Chain FORWARD (policy DROP)' && \
        ip6tables -L | grep -q 'Chain OUTPUT (policy DROP)'
    fi
) ; report "3.5.3.3.3" "Ensure ip6tables default deny firewall policy"

# CIS 3.5.3.3.4
(
    if [ "$iptables_used" = "1" ] && [ -f /proc/net/if_inet6 ] ; then
        proto_ports=($(ss -6tuln | tail -n +2 | awk '{print $1 "/" $5}' | grep -v '::1:' | sed -r 's~(.*)/.*:~\1/~'))

        success=true
        for proto_port in ${proto_ports[@]} ; do
            protocol=${proto_port%%/*}
            port=${proto_port##*/}

            ip6tables -L INPUT -v -n | grep -q "ACCEPT\s+$protocol\s+\*\s+\*\s+::/0\s+::/0\s+$protocol dpt:$port state NEW" || success=false
        done

        [ "$success" = "true" ]
        exit $?
    fi
) ; report "3.5.3.3.4" "Ensure ip6tables firewall rules exist for all open ports"

# CIS 4.1.1.1
(
    dpkg -s auditd &> /dev/null && \
    dpkg -s audispd-plugins &> /dev/null
) ; report "4.1.1.1" "Ensure auditd is installed" "Level 2"

# CIS 4.1.1.2
(
    systemctl is-enabled auditd &> /dev/null
) ; report "4.1.1.2" "Ensure auditd service is enabled" "Level 2"

# CIS 4.1.1.3
(
    [ ! "$(grep '\s*linux' /boot/grub/grub.cfg | grep -v 'audit=1')" ]
) ; report "4.1.1.3" "Ensure auditing for processes that start prior to auditd is enabled" "Level 2"

# CIS 4.1.1.4
(
    [ ! "$(grep '\s*linux' /boot/grub/grub.cfg | grep -v 'audit_backlog_limit=')" ] && \
    backlog_limit=$(grep '\s*linux' /boot/grub/grub.cfg | sed 's/.*\saudit_backlog_limit=//' | awk '{print $1}') && \
    expr "$backlog_limit" \> 8191
) ; report "4.1.1.4" "Ensure audit_backlog_limit is sufficient" "Level 2"

# CIS 4.1.2.1
(
    grep -Eqs '^\s*max_log_file\s*=\s*[1-9][0-9]*' /etc/audit/auditd.conf
) ; report "4.1.2.1" "Ensure audit log storage size is configured" "Level 2"

# CIS 4.1.2.2
(
    grep -Eqs '^\s*max_log_file_action\s*=\s*keep_logs' /etc/audit/auditd.conf
) ; report "4.1.2.2" "Ensure audit logs are not automatically deleted" "Level 2"

# CIS 4.1.2.3
(
    grep -Eqs '^\s*space_left_action\s*=\s*email' /etc/audit/auditd.conf && \
    grep -Eqs '^\s*action_mail_acct\s*=\s*root' /etc/audit/auditd.conf && \
    grep -Eqs '^\s*admin_space_left_action\s*=\s*halt' /etc/audit/auditd.conf
) ; report "4.1.2.3" "Ensure system is disabled when audit logs are full" "Level 2"

# CIS 4.1.3
(
    grep -qs -- '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-a always,exit -F arch=b32 -S clock_settime -k time-change' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /etc/localtime -p wa -k time-change' /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- '-a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change' && \
    auditctl -l 2> /dev/null | grep -q -- '-a always,exit -F arch=b32 -S clock_settime -F key=time-change' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/localtime -p wa -k time-change' && \
    if uname -i | grep -q '64' ; then
        grep -qs -- '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change' /etc/audit/rules.d/*.rules && \
        grep -qd -- '-a always,exit -F arch=b64 -S clock_settime -k time-change' /etc/audit/rules.d/*.rules && \
        auditctl -l 2> /dev/null | grep -q -- '-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change' && \
        auditctl -l 2> /dev/null | grep -q -- '-a always,exit -F arch=b64 -S clock_settime -F key=time-change'
    fi
) ; report "4.1.3" "Ensure events that modify date and time information are collected" "Level 2"

# CIS 4.1.4
(
    grep -qs -- '-w /etc/group -p wa -k identity' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /etc/passwd -p wa -k identity' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /etc/gshadow -p wa -k identity' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /etc/shadow -p wa -k identity' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /etc/security/opasswd -p wa -k identity' /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/group -p wa -k identity' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/passwd -p wa -k identity' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/gshadow -p wa -k identity' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/shadow -p wa -k identity' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/security/opasswd -p wa -k identity'
) ; report "4.1.4" "Ensure events that modify user/group information are collected" "Level 2"

# CIS 4.1.5
(
    grep -qs -- '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /etc/issue -p wa -k system-locale' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /etc/issue.net -p wa -k system-locale' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /etc/hosts -p wa -k system-locale' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /etc/network -p wa -k system-locale' /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- '-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/issue -p wa -k system-locale' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/issue.net -p wa -k system-locale' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/hosts -p wa -k system-locale' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/network -p wa -k system-locale' && \
    if uname -i | grep -q '64' ; then
        grep -qs -- '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale' /etc/audit/rules.d/*.rules && \
        auditctl -l 2> /dev/null | grep -q -- '-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale'
    fi
) ; report "4.1.5" "Ensure events that modify the system's network environment are collected" "Level 2"

# CIS 4.1.6
(
    grep -qs -- '-w /etc/apparmor/ -p wa -k MAC-policy' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /etc/apparmor.d/ -p wa -k MAC-policy' /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/apparmor/ -p wa -k MAC-policy' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/apparmor.d/ -p wa -k MAC-policy'
) ; report "4.1.6" "Ensure events that modify the system's Mandatory Access Controls are collected" "Level 2"

# CIS 4.1.7
(
    grep -qs -- '-w /var/log/faillog -p wa -k logins' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /var/log/lastlog -p wa -k logins' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /var/log/tallylog -p wa -k logins' /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- '-w /var/log/faillog -p wa -k logins' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /var/log/lastlog -p wa -k logins' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /var/log/tallylog -p wa -k logins'
) ; report "4.1.7" "Ensure login and logout events are collected" "Level 2"

# CIS 4.1.8
(
    grep -qs -- '-w /var/run/utmp -p wa -k sessions' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /var/log/wtmp -p wa -k logins' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /var/log/btmp -p wa -k logins' /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- '-w /var/run/utmp -p wa -k session' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /var/log/wtmp -p wa -k logins' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /var/log/btmp -p wa -k logins'
) ; report "4.1.8" "Ensure session initiation information is collected" "Level 2"

# CIS 4.1.9
(
    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) && \
    grep -qs -- "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=$uid_min -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/*.rules && \
    grep -qs -- "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=$uid_min -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/*.rules && \
    grep -qs -- "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S remotexattr -S lremovexattr -S fremovexattr -F auid>=$uid_min -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=$uid_min -F auid!=-1 -F key=perm_mod" && \
    auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=$uid_min -F auid!=-1 -F key=perm_mod" && \
    auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=$uid_min -F auid!=-1 -F key=perm_mod" && \
    if uname -i | grep -q '64' ; then
        grep -qs -- "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=$uid_min -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/*.rules && \
        grep -qs -- "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=$uid_min -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/*.rules && \
        grep -qs -- "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S remotexattr -S lremovexattr -S fremovexattr -F auid>=$uid_min -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/*.rules && \
        auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=$uid_min -F auid!=-1 -F key=perm_mod" && \
        auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=$uid_min -F auid!=-1 -F key=perm_mod" && \
        auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=$uid_min -F auid!=-1 -F key=perm_mod"
    fi
) ; report "4.1.9" "Ensure discretionary access control permission modification events are collected" "Level 2"

# CIS 4.1.10
(
    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) && \
    grep -qs -- "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$uid_min -F auid!=4294967295 -k access" /etc/audit/rules.d/*.rules && \
    grep -qs -- "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$uid_min -F auid!=4294967295 -k access" /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EACCES -F auid>=$uid_min -F auid!=-1 -F key=access" /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EPERM -F auid>=$uid_min -F auid!=-1 -F key=access" /etc/audit/rules.d/*.rules && \
    if uname -i | grep -q '64' ; then
        grep -qs -- "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$uid_min -F auid!=4294967295 -k access" /etc/audit/rules.d/*.rules && \
        grep -qs -- "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$uid_min -F auid!=4294967295 -k access" /etc/audit/rules.d/*.rules && \
        auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=$uid_min -F auid!=-1 -F key=access" && \
        auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=$uid_min -F auid!=-1 -F key=access"
    fi
) ; report "4.1.10" "Ensure unsuccessful unauthorized file access attempts are collected" "Level 2"

# CIS 4.1.11
(
    privileged_commands=($(mount | grep -v noexec | awk '{print $3}' | xargs -i find {} -xdev \( -perm -4000 -o -perm -2000 \) -type f -print))
    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    success=true

    for cmd in ${privileged_commands[@]} ; do
        grep -qs -- "-a always,exit -F path=$cmd -F perm=x -F auid>=$uid_min -F auid!=4294967295 -k privileged" /etc/audit/rules.d/*.rules && \
        auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F path=$cmd -F auid>=$uid_min -F auid!=-1 -F key=privileged" || success=false
    done

    [ "$success" = "true" ]
    exit $?
) ; report "4.1.11" "Ensure use of privileged commands is collected" "Level 2"

# CIS 4.1.12
(
    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) && \
    grep -qs -- "-a always,exit -F arch=b32 -S mount -F auid>=$uid_min -F auid!=4294967295 -k mounts" /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b32 -S mount -F auid>=$uid_min -F auid!=-1 -F key=mounts" && \
    if uname -i | grep -q '64' ; then
        grep -qs -- "-a always,exit -F arch=b64 -S mount -F auid>=$uid_min -F auid!=4294967295 -k mounts" /etc/audit/rules.d/*.rules && \
        auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b64 -S mount -F auid>=$uid_min -F auid!=-1 -F key=mounts"
    fi
) ; report "4.1.12" "Ensure successful file system mounts are collected" "Level 2"

# CIS 4.1.13
(
    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) && \
    grep -qs -- "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=$uid_min -F auid!=4294967295 -k delete" /etc/audit/rules.d/*.rules && \
    auditclt -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=$uid_min -F auid!=-1 -F key=delete" && \
    if uname -i | grep -q '64' ; then
        grep -qs -- "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=$uid_min -F auid!=4294967295 -k delete" /etc/audit/rules.d/*.rules && \
        auditctl -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=$uid_min -F auid!=-1 -F key=delete"
    fi
) ; report "4.1.13" "Ensure file deletion events by users are collected" "Level 2"

# CIS 4.1.14
(
    grep -qs -- '-w /etc/sudoers -p wa -k scope' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /etc/sudoers.d/ -p wa -k scope' /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/sudoers -p wa -k scope' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /etc/sudoers.d/ -p wa -k scope'
) ; report "4.1.14" "Ensure changes to system administration scope (sudoers) is collected" "Level 2"

# CIS 4.1.15
(
    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) && \
    grep -qs -- "-a exit,always -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=$uid_min -F auid!=4294967295 -S execve -k actions" /etc/audit/rules.d/*.rules && \
    auditclt -l 2> /dev/null | grep -q -- "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F auid>=$uid_min -F auid!=-1 -F key=actions" && \
    if uname -i | grep -q '64' ; then
        grep -qs -- "-a exit,always -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=$uid_min -F auid!=4294967295 -S execve -k actions" /etc/audit/rules.d/*.rules && \
        auditctl -l 2> /dev/null | grep -- "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F auid>=$uid_min -F auid!=-1 -F key=actions"
    fi
) ; report "4.1.15" "Ensure system administrator command executions (sudo) are collected" "Level 2"

# CIS 4.1.16
(
    grep -qs -- '-w /sbin/insmod -p x -k modules' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /sbin/rmmod -p x -k modules' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-w /sbin/modprobe -p x -k modules' /etc/audit/rules.d/*.rules && \
    grep -qs -- '-a always,exit -F arch=b32 -S init_module -S delete_module -k modules' /etc/audit/rules.d/*.rules && \
    auditctl -l 2> /dev/null | grep -q -- '-w /sbin/insmod -p x -k modules' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /sbin/rmmod -p x -k modules' && \
    auditctl -l 2> /dev/null | grep -q -- '-w /sbin/modprobe -p x -k modules' && \
    auditctl -l 2> /dev/null | grep -q -- '-a always,exit -F arch=b32 -S init_module,delete_module -F key=modules' && \
    if uname -i | grep -q '64' ; then
        grep -qs -- '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules' /etc/audit/rules.d/*.rules && \
        auditctl -l 2> /dev/null | grep -q -- '-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules'
    fi
) ; report "4.1.16" "Ensure kernel module loading and unloading is collected" "Level 2"

# CIS 4.1.17
(
    grep -s '^\s*[^#]' /etc/audit/rules.d/*.rules | tail -1 | grep -q '-e 2'
) ; report "4.1.17" "Ensure the audit configuration is immutable" "Level 2"

# CIS 4.2.1.1
(
    dpkg -s rsyslog &> /dev/null
) ; report "4.2.1.1" "Ensure rsyslog is installed"

# CIS 4.2.1.2
(
    systemctl is-enabled rsyslog &> /dev/null
) ; report "4.2.1.2" "Ensure rsyslog Service is enabled"

# CIS 4.2.1.3 - Manual

# CIS 4.2.1.4
(
    grep -Eqs '^\s*\$FileCreateMode 06[04]0' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
) ; report "4.2.1.4" "Ensure rsyslog default file permissions configured"

# CIS 4.2.1.5
(
    grep -Eqs '^\s*([^#]+\s+)?action\(([^#]+\s+)?\btarget=\"?[^#"]+\"?\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf || \
    grep -Eqs '^[^#]\s*\S+\.\*\s+@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
) ; report "4.2.1.5" "Ensure rsyslog is configured to send logs to a remote log host"

# CIS 4.2.1.6 - Manual

# CIS 4.2.2.1
(
    grep -Eq '^\s*ForwardToSyslog\s*=\s*yes\s*$' /etc/systemd/journald.conf
) ; report "4.2.2.1" "Ensure journald is configured to send logs to rsyslog"

# CIS 4.2.2.2
(
    grep -Eq '^\s*Compress\s*=\s*yes\s*$' /etc/systemd/journald.conf
) ; report "4.2.2.2" "Ensure journald is configured to compress large log files"

# CIS 4.2.2.3
(
    grep -Eq '^\s*Storage\s*=\s*persistent\s*$' /etc/systemd/journald.conf
) ; report "4.2.2.3" "Ensure journald is configured to write logfiles to persistent disk"

# CIS 4.2.3
(
    [ ! "$(find /var/log -type f -ls | awk '{print $3}' | grep -v '^-rw-r-----' | grep -v '^-rw-------')" ]
) ; report "4.2.3" "Ensure permissions on all logfiles are configured"

# CIS 4.3 - Manual

# CIS 4.4
(
    [ ! "$(grep -Es '^\s*create\s+\S+' /etc/logrotate.conf /etc/logrotate.d/* | grep -Ev '\s(0)?[0-6][04]0\s')" ]
) ; report "4.4" "Ensure logrotate assigns appropriate permissions"

# CIS 5.1.1
(
    systemctl is-enabled cron &> /dev/null && \
    systemctl status cron &> /dev/null
) ; report "5.1.1" "Ensure cron daemon is enabled and running"

# CIS 5.1.2
(
    stat --format='%a %u/%U %g/%G' /etc/crontab | grep -q '600 0/root 0/root'
) ; report "5.1.2" "Ensure permissions on /etc/crontab are configured"

# CIS 5.1.3
(
    stat --format='%a %u/%U %g/%G' /etc/cron.hourly | grep -q '700 0/root 0/root'
) ; report "5.1.3" "Ensure permissions on /etc/cron.hourly are configured"

# CIS 5.1.4
(
    stat --format='%a %u/%U %g/%G' /etc/cron.daily | grep -q '700 0/root 0/root'
) ; report "5.1.4" "Ensure permissions on /etc/cron.daily are configured"

# CIS 5.1.5
(
    stat --format='%a %u/%U %g/%G' /etc/cron.weekly | grep -q '700 0/root 0/root'
) ; report "5.1.5" "Ensure permissions on /etc/cron.weekly are configured"

# CIS 5.1.6
(
    stat --format='%a %u/%U %g/%G' /etc/cron.monthly | grep -q '700 0/root 0/root'
) ; report "5.1.6" "Ensure permissions on /etc/cron.monthly are configured"

# CIS 5.1.7
(
    stat --format='%a %u/%U %g/%G' /etc/cron.d | grep -q '700 0/root 0/root'
) ; report "5.1.7" "Ensure permissions on /etc/cron.d are configured"

# CIS 5.1.8
(
    [ ! -f /etc/cron.deny ] && \
    stat --format='%a %u/%U %g/%G' /etc/cron.allow | grep -q '6[04]0 0/root 0/root'
) ; report "5.1.8" "Ensure cron is restricted to authorized users"

# CIS 5.1.9
(
    [ ! -f /etc/at.deny ] && \
    stat --format='%a %u/%U %g/%G' /etc/at.allow | grep -q '6[04]0 0/root 0/root'
) ; report "5.1.9" "Ensure at is restricted to authorized users"

# CIS 5.2.1
(
    dpkg -s sudo &> /dev/null || dpkg -s sudo-ldap &> /dev/null
) ; report "5.2.1" "Ensure sudo is installed"

# CIS 5.2.2
(
    grep -Eqi '^\s*Defaults\s+([^#]+,\s*)?use_pty(,\s+\S+\s*)*(\s+#.*)?$' /etc/sudoers /etc/sudoers.d/*
) ; report "5.2.2" "Ensure sudo commands use pty"

# CIS 5.2.3
(
    grep -Eqi '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/*
) ; report "5.2.3" "Ensure sudo log file exists"

# CIS 5.3.1
(
    stat --format='%a %u/%U %g/%G' /etc/ssh/sshd_config | grep -q '600 0/root 0/root'
) ; report "5.3.1" "Ensure permissions on /etc/ssh/sshd_config are configured"

# CIS 5.3.2
(
    [ ! "$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat --format='%a %u/%U %g/%G' {} \; | grep -v '600 0/root 0/root')" ]
) ; report "5.3.2" "Ensure permissions on SSH private host key files are configured"

# CIS 5.3.3
(
    [ ! "$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat --format='%a %u/%U %g/%G' {} \; | grep -v '6[04][04] 0/root 0/root')" ]
) ; report "5.3.3" "Ensure permissions on SSH public host key files are configured"

# CIS 5.3.4
(
    sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^(allow|deny)(users|groups)' | grep -Eiq '^(allow|deny)(users|groups)\s+\S+'
) ; report "5.3.4" "Ensure SSH access is limited"

# CIS 5.3.5
(
    sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^loglevel' | grep -Eiq '^loglevel\s+(INFO|VERBOSE)\s*$' && \
    ! grep -Eiqs '^\s*loglevel\s+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Eiqv '(VERBOSE|INFO)'
) ; report "5.3.5" "Ensure SSH LogLevel is appropriate"

# CIS 5.3.6
(
    sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^x11forwarding' | grep -Eiq '^x11forwarding\s+no\s*$' && \
    ! grep -Eiqs '^\s*x11forwarding\s+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
) ; report "5.3.6" "Ensure SSH X11 forwarding is disabled" "Level 2"

# CIS 5.3.7
(
    sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^maxauthtries' | grep -Eiq '^maxauthtries\s+[1-4]\s*$' && \
    ! grep -Eiqs '^\s*maxauthtries\s+([5-9]|[1-9][0-9]+)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
) ; report "5.3.7" "Ensure SSH MaxAuthTries is set to 4 or less"

# CIS 5.3.8
(
    sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^ignorerhosts' | grep -Eiq '^ignorerhosts\s+yes\s*$' && \
    ! grep -Eiqs '^\s*ignorerhosts\s+no\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
) ; report "5.3.8" "Ensure SSH IgnoreRhosts is enabled"

# CIS 5.3.9
(
    sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^hostbasedauthentication' | grep -Eiq '^hostbasedauthentication\s+no\s*$' && \
    ! grep -Eiqs '^\s*hostbasedauthentication\s+yes\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
) ; report "5.3.9" "Ensure SSH HostbasedAuthentication is disabled"

# CIS 5.3.10
(
    sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^permitrootlogin' | grep -Eiq '^permitrootlogin\s+no\s*$' && \
    ! grep -Eiqs '^\s*permitrootlogin\s+(yes|without-password|forced-commands-only)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
) ; report "5.3.10" "Ensure SSH root login is disabled"

# CIS 5.3.11
(
    sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^permitemptypasswords' | grep -Eiq '^permitemptypasswords\s+no\s*$' && \
    ! grep -Eiqs '^\s*permitemptypasswords\s+yes\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
) ; report "5.3.11" "Ensure SSP PermitEmptyPassword is disabled"

# CIS 5.3.12
(
    sshd -T -C user=root -C host="$(hostname)" | grep -Eiq '^permituserenvironment\s+no\s*$' && \
    ! grep -Eiqs '^\s*permituserenvironment\s+yes\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
) ; report "5.3.12" "Ensure SSH PermitUserEnvironment is disabled"

# CIS 5.3.13
(
    [ ! "$(sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^ciphers\s+([^#]+,)?(3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc|rijndael-cbc@lysator.liu.se)\b')" ] && \
    [ ! "$(grep -Eis '^\s*ciphers\s+([^#]+,)?(3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc|rijndael-cbc@lysator\.liu\.se)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf)" ]
) ; report "5.3.13" "Ensure only strong Ciphers are used"

# CIS 5.3.14
(
    [ ! "$(sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^macs\s+([^#]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b')" ] && \
    [ ! "$(grep -Eis '^\s*macs\s+([^#]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf)" ]
) ; report "5.3.14" "Ensure only strong MAC algorithms are used"

# CIS 5.3.15
(
    [ ! "$(sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^kexalgorithms\s+([^#]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b')" ] && \
    [ ! "$(grep -Eis '^\s*kexalgorithms\s+([^#]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf)" ]
) ; report "5.3.15" "Ensure only strong Key Exchange algorithms are used"

# CIS 5.3.16
(
    clientaliveinterval="$(sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^clientaliveinterval' | awk '{print $2}')" && \
    clientalivecountmax="$(sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^clientalivecountmax' | awk '{print $2}')" && \
    [ "$clientaliveinterval" -ge 1 ] && [ "$clientaliveinterval" -le 300 ] && \
    [ "$clientalivecountmax" -ge 1 ] && [ "$clientalivecountmax" -le 3 ] && \
    [ ! "$(grep -Eis '^\s*clientaliveinterval\s+(0|3[0-9][1-9]|3[1-9]0|[4-9][0-9][0-9]|[1-9][0-9][0-9][0-9]+|[6-9]m|[1-9][0-9]+m)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf)" ] && \
    [ ! "$(grep -Eis '^\s*clientalivecountmax\s+(0|[4-9]|[1-9][0-9]+)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf)" ]
) ; report "5.3.16" "Ensure SSH Idle Timeout Interval is configured"

# CIS 5.3.17
(
    logingracetime="$(sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^logingracetime' | awk '{print $2}')" && \
    [ "$logingracetime" -ge 1 ] && [ "$logingracetime" -le 60 ] && \
    [ ! "$(grep -Eis '^\s*logingracetime\s+(0|6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+|[^1]m)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf)" ]
) ; report "5.3.17" "Ensure SSH LoginGraceTime is set to one minute or less"

# CIS 5.3.18
(
    ! sshd -T -C user=root -C host="$(hostname)" | grep -Eiq '^banner\s+"?none"?\s*$' && \
    ! grep -Eiqs '^\s*banner\s+"?none"?\s*$' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
) ; report "5.3.18" "Ensure SSH warning banner is configured"

# CIS 5.3.19
(
    sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^usepam\s+yes\s*$' | grep -Eiq '^usepam\s+yes\s*$' && \
    ! grep -Eiqs '^\s*usepam\s+no\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
) ; report "5.3.19" "Ensure SSH PAM is enabled"

# CIS 5.3.20
(
    sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^allowtcpforwarding' | grep -Eiq '^allowtcpforwarding\s+no\s*$' && \
    ! grep -Eiqs '^\s*allowtcpforwarding\s+yes\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
) ; report "5.3.20" "Ensure SSH AllowTcpForwarding is disabled" "Level 2"

# CIS 5.3.21
(
    maxstartups="$(sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^maxstartups\s+' | awk '{print $2}')" && \
    [ "$(echo $maxstartups | cut -d: -f1)" -le 10 ] && \
    [ "$(echo $maxstartups | cut -d: -f2)" -ge 30 ] && \
    [ "$(echo $maxstartups | cut -d: -f3)" -le 60 ] && \
    [ ! "$(grep -Eis '^\s*maxstartups\s+(((1[1-9]|[1-9][0-9][0-9]+):([0-9]+):([0-9]+))|(([0-9]+):(3[1-9]|4-9][0-9]|[1-9][0-9][0-9]+):([0-9]+))|(([0-9]+):([0-9]+):(6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+)))' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf)" ]
) ; report "5.3.21" "Ensure SSH MaxStartups is configured"

# CIS 5.3.22
(
    [ "$(sshd -T -C user=root -C host="$(hostname)" | grep -Ei '^maxsessions\s+' | awk '{print $2}')" -le 10 ] && \
    ! grep -Eiqs '^\s*maxsessions\s+(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
) ; report "5.3.22" "Ensure SSH MaxSessions is limited"

# CIS 5.4.1
(
    [ "$(grep -Eis '^\s*minlen\s*' /etc/security/pwquality.conf | awk '{print $3}')" -ge 14 ] && \
    ( grep -Eiq '^\s*minclass\s*=\s*4$' /etc/security/pwquality.conf || grep -Eiq '^\s*[duol]credit\s*=\s*-[1-9][0-9]*$' ) && \
    grep -E -q '^\s*password\s+(requisite|required)\s+pam_pwquality\.so\s+(\S+\s+)*retry=[1-3]\s*(\s+\S+\s*)*(\s+#.*)?$' /etc/pam.d/common-password
) ; report "5.4.1" "Ensure password creation requirements are configured"

# CIS 5.4.2
(
    grep -Eq '^auth\s+required\s+pam_tally2\.so\s+onerr=fail\s+(audit )?silent\s+deny=5\s+unlock_time=900\s*$' /etc/pam.d/common-auth && \
    grep -Eq '^account\s+requisite\s+pam_deny\.so\s*$' /etc/pam.d/common-account && \
    grep -Eq '^account\s+required\s+pam_tally2\.so\s*$' /etc/pam.d/common-account
) ; report "5.4.2" "Ensure lockout for failed password attempts is configured"

# CIS 5.4.3
(
    [ ! "$(grep -E '^\s*password\s+required\s+pam_pwhistory\.so' /etc/pam.d/common-password | grep -Ev 'remember=([5-9]|[1-9][0-9]+)\b')" ]
) ; report "5.4.3" "Ensure password reuse is limited"

# CIS 5.4.4
(
    [ ! "$(grep -E '^\s*password\s+(\[success=1\s+default=ignore\]|required)\s+pam_unix\.so\s+([^#]+\s+)?' /etc/pam.d/common-password | grep -v 'sha512')" ]
) ; report "5.4.4" "Ensure password hashing algorithm is SHA-512"

# CIS 5.5.1.1
(
    [ "$(grep -E '^\s*PASS_MIN_DAYS\s+' /etc/login.defs | awk '{print $2}')" -ge 1 ] && \
    [ ! "$(awk -F: '(/^[^:]+:[^!*]/ && $4 < 1){print $1 " " $4}' /etc/shadow)" ]
) ; report "5.5.1.1" "Ensure minimum days between password changes is configured"

# CIS 5.5.1.2
(
    [ "$(grep -E '^\s*PASS_MIN_DAYS\s+' /etc/login.defs | awk '{print $2}')" -le 365 ] && \
    [ ! "$(awk -F: '(/^[^:]+:[^!*]/ && ($5>365 || $5~/([0-1]|-1|\s*)/)){print $1 " " $5}' /etc/shadow)" ]
) ; report "5.5.1.2" "Ensure password expiration is 365 days or less"

# CIS 5.5.1.3
(
    [ "$(grep -E '^\s*PASS_WARN_AGE\s+' /etc/login.defs | awk '{print $2}')" -ge 7 ] && \
    [ ! "$(awk -F: '(/^[^:]+:[^!*]/ && $6<7){print $1 " " $6}' /etc/shadow)" ]
) ; report "5.5.1.3" "Ensure password expiration warning days is 7 or more"

# CIS 5.5.1.4
(
    [ "$(useradd -D | grep 'INACTIVE' | cut -d= -f2)" -le 30 ] && \
    [ ! "$(awk -F: '(/^[^:]+:[^!*]/ && ($7~/(\s*|-1)/ || $7>30)){print $1 " " $7}' /etc/shadow)" ]
) ; report "5.5.1.4" "Ensure inactive password lock is 30 days or less"

# CIS 5.5.1.5
(
    [ ! "$(awk -F: '/^[^:]+:[^!*]/{print $1}' /etc/shadow | while read -r usr; do [ "$(date --date="$(chage --list "$usr" | grep '^Last password change' | cut -d: -f2)" +%s)" -gt "$(date "+%s")" ] && echo "user: $usr password change date: $(chage --list "$usr" | grep '^Last password change' | cut -d: -f2)" ; done )" ]
) ; report "5.5.1.5" "Ensure all users last password change date is in the past"

# CIS 5.5.2
(
    [ ! "$(awk -F: '$1!~/(root|sync|shutdown|halt|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/((\/usr)?\/sbin\/nologin)/ && $7!~/(\/bin)?\/false/ {print}' /etc/passwd)" ] && \
    [ ! "$(awk -F: '($1!~/(root|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/LK?/) {print $1}')" ]
) ; report "5.5.2" "Ensure system accounts are secured"

# CIS 5.5.3
(
    [ "$(grep '^root:' /etc/passwd | cut -f4 -d:)" = "0" ]
) ; report "5.5.3" "Ensure default group for the root account is GID 0"

# CIS 5.5.4
(
    passing=""
    grep -Eiq '^\s*UMASK\s+(0[0-7][2-7]7|[0-7][2-7]7)\b' /etc/login.defs && \
    grep -Eiq '^\s*USERGROUPS_ENAB\s*"?no"?\b' /etc/login.defs && \
    grep -Eq '^\s*session\s+(optional|requisite|required)\s+pam_umask\.so\b' /etc/pam.d/common-session && \
    passing=true

    grep -REiq '^\s*UMASK\s+\s*(0[0-7][2-7]7|[0-7][2-7]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\b' /etc/profile* /etc/bash.bashrc* && \
    passing=true

    [ "$passing" = "true" ] && [ ! "$(grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bash.bashrc*)" ]
    exit $?
) ; report "5.5.4" "Ensure default user umask is 027 or more restrictive"

# CIS 5.5.5
(
    output1=""
    output2=""
    [ -f /etc/bash.bashrc ] && BRC="/etc/bash.bashrc"
    for f in "$BRC" /etc/profile /etc/profile.d/*.sh ; do
        grep -Pq '^\s*([^#]+\s+)?TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' "$f" && \
        grep -Pq '^\s*([^#]+;\s*)?readonly\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' "$f" && \
        grep -Pq '^\s*([^#]+;\s*)?export\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' "$f" && \
        output1="$f"
    done
    grep -Pq '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh "$BRC" && \
    output2=$(grep -Ps '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[0-9][1-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh $BRC)
    
    [ -n "$output1" ] && [ -z "$output2" ]
    exit $?
) ; report "5.5.5" "Ensure default user shell timeout is 900 seconds or less"

# CIS 5.6 - Manual

# CIS 5.7
(
    group_name="$(grep -E '^\s*auth\s+required\s+pam_wheel.so\s+use_uid\s+group=.*\b' /etc/pam.d/su | sed 's/^.*group=//')" && \
    [ "$group_name" ] && \
    grep -Eq "^$group_name:x:.*:$" /etc/group
) ; report "5.7" "Ensure access to the su command is restricted"

# CIS 6.1.1 - Manual

# CIS 6.1.2
(
    stat --format='%a %u/%U %g/%G' /etc/passwd | grep -q '644 0/root 0/root'
) ; report "6.1.2" "Ensure permissions on /etc/passwd are configured"

# CIS 6.1.3
(
    stat --format='%a %u/%U %g/%G' /etc/passwd- | grep -q '6[04][04] 0/root 0/root'
) ; report "6.1.3" "Ensure permissions on /etc/passwd- are configured"

# CIS 6.1.4
(
    stat --format='%a %u/%U %g/%G' /etc/group | grep -q '644 0/root 0/root'
) ; report "6.1.4" "Ensure permissions on /etc/group are configured"

# CIS 6.1.5
(
    stat --format='%a %u/%U %g/%G' /etc/group- | grep -q '6[04][04] 0/root 0/root'
) ; report "6.1.5" "Ensure permissions on /etc/group- are configured"

# CIS 6.1.6
(
    stat --format='%a %u/%U %G' /etc/shadow | grep -Eq '6[04]0 0/root (root|shadow)'
) ; report "6.1.6" "Ensure permissions on /etc/shadow are configured"

# CIS 6.1.7
(
    stat --format='%a %u/%U %G' /etc/shadow- | grep -Eq '6[04]0 0/root (root|shadow)'
) ; report "6.1.7" "Ensure permissions on /etc/shadown- are configured"

# CIS 6.1.8
(
    stat --format='%a %u/%U %G' /etc/gshadow | grep -Eq '6[04]0 0/root (root|shadow)'
) ; report "6.1.8" "Ensure permissions on /etc/gshadow are configured"

# CIS 6.1.9
(
    stat --format='%a %u/%U %G' /etc/gshadow- | grep -Eq '6[04]0 0/root (root|shadow)'
) ; report "6.1.9" "Ensure permissions on /etc/gshadow- are configured"

# CIS 6.1.10
(
    [ ! "$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002)" ]
) ; report "6.1.10" "Ensure no world writable files exist"

# CIS 6.1.11
(
    [ ! "$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)" ]
) ; report "6.1.11" "Ensure no unowned files or directories exist"

# CIS 6.1.12
(
    [ ! "$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup)" ]
) ; report "6.1.12" "Ensure no ungrouped files or directories exist"

# CIS 6.1.13 - Manual

# CIS 6.1.14 - Manual

# CIS 6.2.1
(
    [ ! "$(awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}' /etc/passwd)" ]
) ; report "6.2.1" "Ensure accounts in /etc/passwd use shadowed passwords"

# CIS 6.2.2
(
    [ ! "$(awk -F: '($2 == "") { print $1 " does not have a password "}' /etc/shadow)" ]
) ; report "6.2.2" "Ensure password fields are not empty"

# CIS 6.2.3
(
    success=true
    for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
        grep -Pq "^.*?:[^:]*:$i:" /etc/group || success=false
    done

    [ "$success" = "true" ]
    exit $?
) ; report "6.2.3" "Ensure all groups in /etc/passwd exist in /etc/group"

# CIS 6.2.4
(
    success=true
    awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $1 " " $6 }' /etc/passwd | while read -r user dir; do
        [ -d "$dir" ] || success=false
    done

    [ "$success" = "true" ]
    exit $?
) ; report "6.2.4" "Ensure all users' home directories exist"

# CIS 6.2.5
(
    success=true
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
        [ -d "$dir" ] && [ "$(stat -L -c "%U" "$dir")" = "$user" ] || success=false
    done

    [ "$success" = "true" ]
    exit $?
) ; report "6.2.5" "Ensure users own their home directories"

# CIS 6.2.6
(
    success=true
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
        [ -d "$dir" ] && stat -L -c "%A" "$dir" | grep -q '.....-.---' || success=false
    done

    [ "$success" = "true" ]
    exit $?
) ; report "6.2.6" "Ensure users' home directories permissions are 750 or more restrictive"

# CIS 6.2.7
(
    success=true
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
        if [ -d "$dir" ] ; then
            for file in "$dir"/.*; do
                if [ ! -h "$file" ] && [ -f "$file" ]; then
                    stat -L -c "%A" "$file" | grep -q '.....-..-.' || success=false
                fi
            done
        fi
    done

    [ "$success" = "true" ]
    exit $?
) ; report "6.2.7" "Ensure users' dot files are not group or world writable"

# CIS 6.2.8
(
    success=true
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
        if [ -d "$dir" ] ; then
            if [ ! -h "$dir/.netrc" ] && [ -f "$dir/.netrc" ] ; then
                stat -L -c "%A" "$dir/.netrc" | grep -q '...-------' || success=false
            fi
        fi
    done

    [ "$success" = "true" ]
    exit $?
) ; report "6.2.8" "Ensure no users have .netrc files"

# CIS 6.2.9
(
    success=true
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
        [ -d "$dir" ] && [ ! -h "$dir/.forward" ] && [ -f "$dir/.forward" ] || success=false
    done

    [ "$success" = "true" ]
    exit $?
) ; report "6.2.9" "Ensure no users have .forward files"

# CIS 6.2.10
(
    success=true
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
        [ -d "$dir" ] && [ ! -h "$dir/.rhosts" ] && [ -f "$dir/.rhosts" ] || success=false
    done

    [ "$success" = "true" ]
    exit $?
) ; report "6.2.10" "Ensure no users have .rhosts files"

# CIS 6.2.11
(
    [ "$(awk -F: '($3 == 0) {print $1}' /etc/passwd)" = "root" ]
) ; report "6.2.11" "Ensure root is the only UID 0 account"

# CIS 6.2.12
(
    success=true
    RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
    echo "$RPCV" | grep -q "::" && success=false
    echo "$RPCV" | grep -q ":$" && success=false
    for x in $(echo "$RPCV" | tr ":" " ") ; do
        [ -d "$x" ] && [ "$x" != "." ] && stat -L -c "%A" "$x" | grep -q '.....-..-.' || success=false
    done

    [ "$success" = "true" ]
    exit $?
) ; report "6.2.12" "Ensure root PATH Integrity"

# CIS 6.2.13
(
    success=true
    cut -f3 -d: /etc/passwd | sort -n | uniq -c | while read x ; do
        [ -z "$x" ] && break
        set - $x
        [ $1 -gt 1 ] && success=false
    done

    [ "$success" = "true" ]
    exit $?
) ; report "6.2.13" "Ensure no duplicate UIDs exist"

# CIS 6.2.14
(
    [ ! "$(cut -f3 -d: /etc/group | sort -n | uniq -d)" ]
) ; report "6.2.14" "Ensure no duplicate GIDs exist"

# CIS 6.2.15
(
    [ ! "$(cut -f1 -d: /etc/passwd | sort | uniq -d)" ]
) ; report "6.2.15" "Ensure no duplicate user names exist"

# CIS 6.2.16
(
    [ ! "$(cut -f1 -d: /etc/group | sort | uniq -d)" ]
) ; report "6.2.16" "Ensure no duplicate group names exist"

# CIS 6.2.17
(
    [ ! "$(awk -F: '($1=="shadow") {print $NF}' /etc/group)" ] && \
    [ ! "$(awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print $1}' /etc/passwd)" ]
) ; report "6.2.17" "Ensure shadow group is empty"
