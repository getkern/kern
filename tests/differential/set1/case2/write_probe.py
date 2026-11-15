import sys
try:
    open("/etc/passwd", "a").write("x")
    print("WRITE_OK")
    sys.exit(0)
except Exception as e:
    print("WRITE_DENIED", type(e).__name__)
    sys.exit(2)
