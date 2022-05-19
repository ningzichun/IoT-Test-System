from machine import Pin
import network
import dht
def command_status(**kw):
    d = dht.DHT11(Pin(4))
    d.measure()
    return {
        "code":200,
        "status":{
            "wlan": network.WLAN(network.STA_IF).ifconfig(),
            "environment_temperature": d.temperature(),
            "environment_humidity": d.humidity(),
        }
    }

def command_led(**kw):
    led = Pin(2,Pin.OUT)
    led.value(not led.value())
    return {
        "code":200,
        "status":{
            "led": led.value(),
            "led_on_board": "灭" if led.value() else "亮",
        }
    }

commandList={
    "status":{
        'info':"获取传感器状态",
        'command':command_status,
    },
    "led":{
        'info':"操作LED灯",
        'command':command_led,
    }
}

commandInfo = {
    "status":{
        'info':"获取传感器状态",
        'input': 'none'
    },
    "led":{
        'info':"操作LED灯",
        'input': 'none'
    }
}
guiLayout={

}

