FROM ubuntu:20.04

RUN apt-get update && apt-get install -y openssh-server sudo && \
    mkdir /var/run/sshd && \
    echo 'root:password' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    # SSH1 protocol (vulnerable)
    echo 'Protocol 2,1' >> /etc/ssh/sshd_config && \
    # Weak ciphers
    echo 'Ciphers aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour' >> /etc/ssh/sshd_config && \
    # Weak MACs
    echo 'MACs hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160' >> /etc/ssh/sshd_config

# Create a test user
RUN useradd -rm -d /home/testuser -s /bin/bash -g root -G sudo -u 1000 testuser && \
    echo 'testuser:testpassword' | chpasswd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]