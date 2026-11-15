mkdir -p sshd keys
ssh-keygen -t ed25519 -N "" -f keys/id_ed25519 -q
cp keys/id_ed25519.pub sshd/authorized_keys
ssh-keygen -t ed25519 -N "" -f keys/wrong -q
