FROM ubuntu:22.04

# Install OpenSSH server
RUN apt-get update && \
    apt-get install -y openssh-server && \
    rm -rf /var/lib/apt/lists/*

# Create the SSH run directory
RUN mkdir -p /var/run/sshd

# Create a user for SSH access
RUN useradd -m -s /bin/bash sshuser && \
    echo 'sshuser:SecurePass2024!' | chpasswd

# Create flag file (FLAG 2)
RUN mkdir -p /home/sshuser/secrets && \
    echo 'FLAG{h1dd3n_s3rv1c3s_n33d_pr0t3ct10n}' > /home/sshuser/secrets/flag2.txt && \
    chown -R sshuser:sshuser /home/sshuser/secrets && \
    chmod 400 /home/sshuser/secrets/flag2.txt

# Create a welcome message
RUN echo '#!/bin/bash' > /home/sshuser/.bashrc && \
    echo 'echo "=========================================="' >> /home/sshuser/.bashrc && \
    echo 'echo "Welcome to the Secret SSH Server!"' >> /home/sshuser/.bashrc && \
    echo 'echo "You have discovered a hidden service!"' >> /home/sshuser/.bashrc && \
    echo 'echo "=========================================="' >> /home/sshuser/.bashrc && \
    echo 'echo ""' >> /home/sshuser/.bashrc && \
    echo 'echo "Your flag is located in: ~/secrets/flag2.txt"' >> /home/sshuser/.bashrc && \
    echo 'echo ""' >> /home/sshuser/.bashrc && \
    echo 'export PS1="\[\033[01;32m\]sshuser@secret-server\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "' >> /home/sshuser/.bashrc

# Copy SSH configuration and banner
COPY sshd_config /etc/ssh/sshd_config
COPY banner /etc/ssh/banner

# Expose SSH on port 2222 (non-standard port - students must discover this)
EXPOSE 2222

# Start SSH server
CMD ["/usr/sbin/sshd", "-D", "-p", "2222"]
