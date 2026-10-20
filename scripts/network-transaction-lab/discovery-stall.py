"""Disposable read-only collector fault: sustained output until the production budget kills it."""
import os
import time
while True:
    os.write(1,b'x'*65536)
    time.sleep(.01)
