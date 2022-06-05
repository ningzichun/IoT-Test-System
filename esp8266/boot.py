print("\n\nHello!\n")
import time
def connect_wlan():
    import network
    ssid = "sdu_net"
    password =  None
    station = network.WLAN(network.STA_IF)
    if station.isconnected() == True:
        print("Already connected")
        return
    station.active(True)
    station.connect(ssid, password)
    while station.isconnected() == False:
        pass
    print("Connection successful")
    print(station.ifconfig())
connect_wlan()
