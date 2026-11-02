import subprocess
import time

p = subprocess.Popen(
    ['./target/debug/p2p-cli', '--nick', 'AutoTester', '--daemon', '--connect', '/ip4/168.75.92.194/tcp/9000/p2p/12D3KooWBgNBwYnH1Fng6XJdokqLeUWH4vXZssJ9xrggbgKg2ZyC'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

time.sleep(3)
p.stdin.write('/send Oracle-Bot send_test.bin\n')
p.stdin.flush()
time.sleep(4)
p.stdin.write('/quit\n')
p.stdin.flush()
p.wait(timeout=10)
print('Done!')
