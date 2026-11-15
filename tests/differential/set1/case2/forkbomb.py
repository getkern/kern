import os, time
for _ in range(1000):
    try:
        if os.fork() == 0:
            time.sleep(30)
    except OSError as e:
        print("FORK_LIMIT", e.errno)
        raise SystemExit(3)
time.sleep(5)
print("FORK_UNEXPECTED_OK")
