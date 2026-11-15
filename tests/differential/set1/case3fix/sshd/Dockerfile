FROM alpine:3.20
RUN apk add --no-cache openssh-server openssh-sftp-server openssh-client \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh app \
 && passwd -u app \
 && mkdir -p /home/app/.ssh /run/sshd \
 && chmod 700 /home/app/.ssh
COPY authorized_keys /home/app/.ssh/authorized_keys
RUN chown -R app:app /home/app/.ssh \
 && chmod 600 /home/app/.ssh/authorized_keys \
 && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config \
 && sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config \
 && sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
 && echo "AllowUsers app" >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
