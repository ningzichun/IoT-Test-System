
print("\n\nHello!\n")
import network
wlan = network.WLAN(network.STA_IF)
wlan.active(True)

import time
def connect_wlan():
    while not wlan.isconnected():
        print("Connecting to network...")
        wlan.connect("ning", "123123123")  # 设置 SSID 密码
        time.sleep(2)
        if not wlan.isconnected():
            print("Not connected")
    print("Connected, Network config:", wlan.ifconfig())
    return True

connect_wlan()
