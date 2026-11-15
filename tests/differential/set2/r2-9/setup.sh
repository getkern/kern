mkdir -p /tmp/kern-r2-out proj
echo OUTSIDE > /tmp/kern-r2-out/outside.txt
ln -sfn /tmp/kern-r2-out proj/link-out
echo INSIDE > proj/inside.txt
# file owned by other uid (need root once, or skip ownership check if not root)
sudo chown 12345:12345 proj/inside.txt 2>/dev/null || chown 12345 proj/inside.txt 2>/dev/null || true
