import time

import socket

import struct
import json
import network

DEFAULT_SERVER_PORT = 20020

from device import commandList,commandInfo

### 客户端配置部分

config= {}

connectedNodeInfo = [None,None] # ID ADDR


def commandHandler(data):   # 设备数据处理
    if data["command"] not in commandList:
        return {
            "code": 404,
            "msg":"No such command"
        }
    else:
        input_data = data["kw"] if "kw" in data else {}
        return_data = commandList[data["command"]]["command"](**input_data)
        return return_data

def initNode(): # 初始化客户端配置
    global config
    try:    # 读取配置文件
        with open('./client.json','r',encoding='utf-8') as f:
            config = json.load(f)
    except Exception:
        pass

    # 填充默认值
    if "id" not in config:
        config["id"]=genID()

    if "role" not in config:
        config["role"]=[
            "client",
            "embedded"
        ]

    if "name" not in config:  # 使用hostname填充友好名称
        config["name"]="ESP8266_"+str(time.time_ns())[3:7]

    if "model" not in config:
        config["model"] = "ESP8266_Genetic"

    # save config file
    with open('./client.json','w') as f:
        f.write(json.dumps(config))
        f.close()

    config['status'] = 'disconnected'
    print("Initialized\n",config)

def genID():    # 生成本机ID
    return "".join([hex(i)[2:] if len(hex(i)[2:])>1 else "0"+hex(i)[2:] for i in network.WLAN(network.STA_IF).config("mac")])+str(time.time_ns())[3:7]

def fillFrom(): # 填充from项
    fromDict={
        "id":config["id"],
        "role": config["role"],
        "name": config["name"],
    }
    return fromDict


### 事件处理模块

event = {   # 事件列表
#   "eventID":  [register_time, timeout_time, data ]
}

def newEvent(timeout=3600,data=None):   # 新建事件
    time_ns = time.time_ns()
    eventID = hex(time_ns)[2:]
    event[eventID] = [time.time(),time.time()+timeout,data]
    return eventID

def calcEvent(eventID, end_time = time.time(),reset_timeout = 0):   # 计算事件存在事件
    if eventID not in event:
        return False
    if reset_timeout:
        event[eventID][1] = time.time()+reset_timeout
    return end_time - event[eventID][0]

def getEventData(eventID):  # 获取事件数据
    if eventID not in event:
        return False
    return event[eventID][2]

def setEventData(eventID,data): # 设置事件数据
    if eventID not in event:
        return False
    event[eventID][2] = data
    return True

def deleteExpiredEvent():   # 删除过期的事件
    current_time = time.time()
    for k in event.keys():
        v = event[k]
        if v[1]<current_time:
            event.pop(k)
    return True

def checkIncomingEvent(incoming,timeout=3600):    # 记录远程事件序号（判定重复）
    eventID = 'IN'+incoming
    if eventID not in event:
        event[eventID] = [time.time(),time.time()+timeout]
        return True # 返回True，第一次
    return False    # 非第一次，返回False

### 与服务节点稳定连接，认证与保持
stableConnectionList = {}
authorizedToken = {}
def updateStableConnectionNode(nodeid,token):
    if nodeid not in stableConnectionList:
        stableConnectionList[nodeid] = {'token':token,'time':time.time()}
    else:
        stableConnectionList[nodeid]['token']=token;stableConnectionList[nodeid]['time']=time.time()
def lostStableConnectionNode(nodeid):
    if nodeid in stableConnectionList:
        stableConnectionList.pop(nodeid)

def genAuthorizedToken(nodeid):
    token = str(time.time_ns())
    authorizedToken[nodeid] = token # Expired time?
    return token

def checkConnectionStatus():
    pass

### 设备网络信息，调试及数据处理部分

def fillFromData(): # 填充from项
    data,data_hash = getSelfStatus()
    fromDict={
        "id":config["id"],
        "time":time.time(),
        "data":data,
        "hash":data_hash
    }
    return fromDict

def getSelfStatus():    # 返回客户端自身信息
    if connectedNodeInfo[0]:
        config['status'] = 'connected'
    data = {
        'name':config['name'],
        'role':config['role'],
    }
    if connectedNodeInfo[0]:
        data['forwarder'] = connectedNodeInfo # To be Finished
    if 'model' in config:   # 有型号
        data['model'] = config['model']
    return data,calcHash(data)

def calcHash(data):
    return hash(str(data))


socket_tcp = None

def TCPRecvHandler(conn:socket.socket()):
    rawdata_len = conn.recv(4)
    if not rawdata_len:
        return False
    rawdata_len = struct.unpack('i',rawdata_len)[0]
    rawdata = conn.recv(rawdata_len)
    if not rawdata:
        return False
    # 解码到dict
    try:
        data = json.loads(rawdata)
        if 'action' not in data:
            return False
    except Exception as e:
        print(repr(e))
        return False
    TCPDataHandler(data)

def TCPSendHandler(rawdata):
    global socket_tcp
    print("发送 "+str(rawdata['action'])+" 数据包")
    data=json.dumps(rawdata).encode()
    socket_tcp.sendall(struct.pack('i',len(data)))
    socket_tcp.sendall(data)
    return True

def TCPDataHandler(data):
    print("收到 "+str(data['action'])+" 数据包，来自 "+str(data['from']['id']))

    if data['action'] == 'establish':   # 建立稳定连接，例如需要认证，返回token
        token = genAuthorizedToken(data['from']['id'])
        TCPSendHandler({
            "to":{"id":data['from']['id']},
            "action": "ackestablish",
            "from": fillFrom(),
            "event":data['event'],
            'data':{'token':token}
        })
        return True

    if data['action'] == 'ackestablish':    # 获得了来自服务节点的认证
        #updateStableConnectionNode(data['from']['id'],data['data']['token'])
        connectedNodeInfo[0] = data['from']['id']
        return True
    if data['action'] == 'commandlist': # 获取设备的命令列表
        print("事件号为",data["event"])
        report_data = {
            "to":{"id":data['from']['id']},
            "from": fillFrom(),
            "action": "ackcommandlist",
            "event": data["event"],
            "data": commandInfo
        }
        TCPSendHandler(report_data)
        return True
    if data["action"]=="command":   # 给设备下指令
        print("事件号为 ",data["event"])
        if not checkIncomingEvent(data['from']['id']+data['event']):
            return False    # 已经处理过这个事件了，忽略
        report_data = {
            "to":{"id":data['from']['id']},
            "from": fillFrom(),
            "action": "ackcommand",
            "event": data["event"],
            "data": commandHandler(data["data"])
        }
        TCPSendHandler(report_data)

def establishConnection():
    global socket_tcp
    certNode = socket.getaddrinfo('iot.mrning.com', 20020)[0][-1] # ('119.91.219.109', 20020)
    socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_tcp.bind(('',DEFAULT_SERVER_PORT))
    socket_tcp.setsockopt(socket.SOL_SOCKET, 20, TCPRecvHandler)    # 设置回调
    try:
        socket_tcp.connect(certNode)
        print("Connected to ",certNode)
        connectedNodeInfo[1] = certNode
        TCPSendHandler({
            'from':fillFromData(),
            'action':'establish',   # 也可以加上认证
            'event':newEvent(),
        })
        return True
    except Exception as e:
        print(repr(e))
        return False
initNode()

establishConnection()

