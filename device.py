
def command_reboot(**kw):
    from os import system
    system('reboot')

def command_status(**kw):
    import psutil
    # disk=[]
    # for i in psutil.disk_partitions():
    #     disk[i[1]]=list(psutil.disk_usage(i[1]))
    return {
        "code":200,
        "status":{
            "cpu_count":psutil.cpu_count(),
            "cpu_freq":list(psutil.cpu_freq()),
            "cpu_percent":psutil.cpu_percent(),
            "boot_time":psutil.boot_time(),
            "virtual_memory" : list(psutil.virtual_memory()),
            "swap_memory" : list(psutil.swap_memory()),
            "net_io_counters" : list(psutil.net_io_counters()),
            # "disk":disk,
            # 网速
        }
    }

def command_cmd(**kw):
    import os 
    if "cmd" not in kw:
        return {"code":403,"msg":"No cmd argument"} 
    else:
        rs = os.popen(kw['cmd'])
        return {"code":200,"msg":rs.read()}

commandList={
    "reboot":{
        'info':"重启设备",
        'command':command_reboot,
    },
    "status":{
        'info':"获取系统状态",
        'command':command_status,
    },
    "cmd":{
        'info':"执行命令",
        'command':command_cmd,
    }
}

commandInfo = {
    "reboot":{
        'info':"重启设备",
        'input': 'none'
    },
    "status":{
        'info':"获取系统状态",
        'input': 'none'
    },
    "cmd":{
        'info':"执行命令",
        'input': {
            'name':'cmd',
            'type': 'text'
        }
    }
}
guiLayout={
    
}

