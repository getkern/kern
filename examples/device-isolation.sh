#!/bin/sh
# Give a container exactly one hardware device - and nothing else.
#
# kern binds only the device you name into the box; every other host device
# stays absent (deny-by-default). Handy on edge boards: a sensor on i2c, a
# serial MCU, or a SPI peripheral - exposed to one workload, kept away from the
# rest of the system. Device access is node-granular (a whole /dev node), which
# is a real kernel boundary; see SECURITY.md for the GPIO-line caveat.
set -eu
kern="${KERN:-kern}"

# Pick a device that actually exists on this host, and the matching profile field.
dev=""; field=""
for cand in /dev/i2c-1 /dev/i2c-0 /dev/ttyUSB0 /dev/ttyACM0 /dev/spidev0.0; do
  [ -e "$cand" ] || continue
  case "$cand" in
    /dev/i2c-*)   field="i2c" ;;
    /dev/tty*)    field="uart" ;;
    /dev/spidev*) field="spi" ;;
  esac
  dev="$cand"; break
done

if [ -z "$dev" ]; then
  echo "No i2c/serial/spi device on this host to demo with."
  echo "On a Pi/Jetson/Arduino you'd expose e.g. an i2c sensor:"
  echo "    [[vgpio]]"
  echo "    name = \"sensor\""
  echo "    i2c  = [\"/dev/i2c-1\"]"
  echo "  then:  kern box app --image alpine vgpio:sensor -- ./read-sensor"
  exit 0
fi

cfg="$(mktemp -d)/kern.toml"
cat > "$cfg" <<EOF
[[vgpio]]
name = "sensor"
$field = ["$dev"]
EOF

echo "==> exposing only $dev into the box (profile vgpio:sensor):"
echo
"$kern" box hw --image alpine --config "$cfg" vgpio:sensor -- sh -c '
  echo "  device nodes in the box:";
  ls -1 /dev | grep -E "^(i2c-|tty(USB|ACM|S)|spidev|gpiochip)" | sed "s/^/    /" || true
  echo;
  echo "  host disks in the box?";
  if ls /dev/nvme* /dev/sd* /dev/mmcblk* 2>/dev/null | grep -q .; then
    echo "    LEAK: host disks visible"; else echo "    none - host storage is not exposed"; fi
'

echo
echo "The box saw one device and nothing else. Everything is discarded on exit."
rm -rf "$(dirname "$cfg")"
