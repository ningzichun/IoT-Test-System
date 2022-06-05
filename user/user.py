### 用户端API
'''
需要的功能有
发现网络中的Forwarder服务节点
请求Client列表并展示
连接到Client
'''

import socket
import threading
import socket
import threading
import time
# import psutil
import json
import pickle
import ipaddress
import random
import struct
import os
import queue
import string


config= {}
DEFAULT_SERVER_PORT = 20020

import dns.resolver
certNodeList = [("iot.mrning.com",20020)]   # 预设节点列表 [(domain|ip,port),addr2]


def initNode(): # 初始化节点配置
    global config
    try:    # 尝试获取本地的配置文件
        with open('./user.json','r',encoding='utf-8') as f:
            config = json.load(f)
    except Exception:
        pass

    # 填充默认值
    if "id" not in config:
        config["id"]=genID()

    if "role" not in config:    # 默认的节点参与的角色
        config["role"]=[
            "user",
        ]

    if "name" not in config:    # 使用hostname填充友好名称
        config["name"]=socket.gethostname()

    # save config file
    with open('./user.json','w') as f:
        f.write(json.dumps(config))
        f.close()
    
    print("Initialized\n",config)

def genID():    # 生成本机ID
    import uuid
    return str(uuid.uuid1())

def fillFrom(): # 填充from项
    fromDict={
        "id":config["id"],
        "role": config["role"],
        "name": config["name"],
    }
    return fromDict

def fillFromData(): # 填充from项
    data,data_hash = getSelfStatus()
    fromDict={
        "id":config["id"],
        'time':time.time(),
        "data":data,
        "hash":data_hash
    }
    return fromDict



### 设备网络信息，调试及数据处理部分

def encryptData(rawdata):   # 加密数据
    #return json.dumps(rawdata).encode('utf-8')
    return pickle.dumps(rawdata)

def decryptData(rawdata):   # 解密数据
    #return json.loads(rawdata.decode('utf-8'))
    return pickle.loads(rawdata)

def logInfo(*info):
    print(time.strftime('[%Y-%m-%d %H:%M:%S]',time.localtime()),"INFO:",' '.join(map(str,info)))

def logErr(*info):
    print(time.strftime('[%Y-%m-%d %H:%M:%S]',time.localtime()),"ERROR:",' '.join(map(str,info)))

def calcScore(latency): # 根据间隔时间计算连接质量
    if latency>0 and latency<100:
        return 100-latency*0.5
    if latency<=0:
        return 0
    return 52-(latency*0.02)

# def getInterface(): # 获取网卡信息
#     net_if_addrs = psutil.net_if_addrs()
#     interfaces = []
#     for k in net_if_addrs:
#         # a new net_interface
#         netif = {'name': k}
#         for v in net_if_addrs[k]:   #snicaddr(family=<AddressFamily.AF_LINK: -1>, address='AA-BB-', netmask=None, broadcast=None, ptp=None)
#             # check address
#             try:
#                 if v[0] == psutil.AF_LINK:  #MAC
#                     netif['mac'] = v[1]
#                 elif v[0] == socket.AddressFamily.AF_INET:  #IPv4
#                     v4 = ipaddress.IPv4Address(v[1])
#                     if v4.is_global:
#                         if "ipv4" not in netif:
#                             netif["ipv4"] = []
#                         netif["ipv4"].append({
#                             'ip': v[1],
#                             'type': 'global',
#                         })
#                     elif v4.is_private:
#                         if v4.is_link_local or v4.is_loopback or v4.is_reserved:
#                             continue
#                         if "ipv4" not in netif:
#                             netif["ipv4"] = []
#                         netif["ipv4"].append({
#                             'ip': v[1],
#                             'type': 'private',
#                         })
#                 elif v[0] == socket.AddressFamily.AF_INET6: #IPv6
#                     v6 = ipaddress.IPv6Address(v[1])
#                     if v6.is_global:
#                         if "ipv6" not in netif:
#                             netif["ipv6"] = []
#                         netif["ipv6"].append({
#                             'ip': v[1],
#                             'type': 'global',
#                         })
#             except Exception:
#                 pass
#         if "ipv4" in netif or "ipv6" in netif:
#             interfaces.append(netif)
#     return interfaces

# def getIPs():   # 从网卡信息中读取IP
#     interfaces = getInterface()
#     IPs={"global":[],"private":[]}
#     for i in interfaces:
#         if "ipv4" in i:
#             for v4 in i["ipv4"]:
#                 if v4["type"] == "global":
#                     IPs["global"].append({
#                         "ip": v4["ip"],
#                         "name": i["name"],
#                     })
#                 else:
#                     IPs["private"].append({
#                         "ip": v4["ip"],
#                         "name": i["name"],
#                     })
#         if "ipv6" in i:
#             for v6 in i["ipv6"]:
#                 if v6["type"] == "global":
#                     IPs["global"].append({
#                         "ip": v6["ip"],
#                         "name": i["name"],
#                     })
#     return IPs

# def getGlobalIPs(): # 获取全局IP地址
#     IPs = getIPs()['global']
#     globalIPs = [i['ip'] for i in IPs]
#     return globalIPs

def isIP(addr): # 判断是否为IP及版本号
    cnt_dot = 0 # 点
    cnt_colon = 0   # 冒号
    cnt_num = 0 # 数字
    cnt_ch = 0  # 其他字符
    for i in addr:
        if i=='.':
            cnt_dot +=1
        elif i==":":
            cnt_colon +=1
        elif '0'<=i and i<='9':
            cnt_num += 1
        else:
            cnt_ch+=1
    if cnt_ch==0 and cnt_dot==3:    # IPv4
        return 4
    if cnt_colon:   # IPv6
        return 6
    return False    # 域名


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

def deleteExpiredEvent():   # 删除过期的事件，待实现
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



#   分布式节点获取，用户节点版本



networkList = { # 对于Python3.6+，Dict插入有序；Python3.8支持reversed返回key的iter
    #   'id':   'time0','hash1','data2','latency3'
}

UDPPingIDQueue = queue.Queue()

def UDPPingID():
    while True:
        target_id = UDPPingIDQueue.get()
        if target_id in networkList:
            eventID = newEvent()
            for iterAddr in networkList[target_id][2]['addr']:
                UDPSendHandler({
                "action": "ping",
                "event":eventID
            },iterAddr)


def calcHash(data):
    return hash(str(data))


def genConnectedNodeInfo(): # 获取已连接客户端节点
    return_list = []
    for k,v in stableConnectionList:    # id, time, hash, data
        return_list.append([k,networkList[k][0],networkList[k][1],networkList[k][2]])

def getSelfStatus():    # 返回客户端自身信息
    if len(stableConnectionList)>0:
        config['status'] = 'connected'
    data = {
        'name':config['name'],
        'role':config['role'],
    }
    if config['addr']:  # 拥有公网地址
        data['addr']=config['addr']
    if 'storage' in config: # 有存储需求
        data['storage'] = config['storage']
    return data,calcHash(data)


def getNetworkListData(target_list):    # 返回对端要求的networkList
    data = {}   #   [['id0','time1','hash2','data',latency4]]
    for i in target_list:
        if i in networkList:
            data.append([i,networkList[i][0],networkList[i][1],networkList[i][2],networkList[i][3]])
    return data

def diffNetworkList(target_list):  # 发现有数据更改的节点，修改数据，并返回过期数据的ID
    global networkList
    expiredList = []    # target_list: [['id0','time1','hash2]]
    for each in target_list:
        if each[0] in networkList:  # 存在ID
            if each[2] != networkList[each[0]][1]:  # hash不同！
                if each[1]>networkList[each[0]][0]: # 存在新的数据
                    expiredList.append(each[0]) # 加入ID
            else:   # hash相同，更新时间
                networkList[each[0]][0] = max(networkList[each[0]][0], each[1])
        else:
            expiredList.append(each[0]) # 加入ID
    return expiredList

def updateNetworkList(target_list):    # 拥有data，更新networkList
    global networkList
    cnt = 0
    client_list = []
    for each in target_list:    # target_list: [['id0','time1','hash2','data3']]
        # 额外判断下client
        if 'client' in each[3]:
            client_list.append(each)
        if each[0] in networkList:  # 存在ID
            if each[2] != networkList[each[0]][1]:  # hash不同
                if each[1]>networkList[each[0]][0]: # 存在新的数据，更新networkList
                    networkList.pop(each[0])
                    networkList[each[0]]={[each[1],each[2],each[3]]};cnt+=1
            else:   # hash相同，更新时间
                tmp_value = networkList[each[0]]
                tmp_value[0] = max(tmp_value[0], each[1])
                networkList.pop(each[0])
                networkList[each[0]] = tmp_value;cnt+=1
        else:   # 不存在ID，新建
            networkList[each[0]] = [each[1],each[2],each[3],False];cnt+=1
            UDPPingIDQueue.put_nowait(each[0])
    updateClientList(client_list)
    return cnt

def getNetworkListDataHandler(target_list): # 获取要求的节点信息列表
    global networkList
    return_list = []
    for i in target_list:
        if i in networkList:   # [['id0','time1','hash2','data3']]
            return_list.append([i,networkList[i][0],networkList[i][1],networkList[i][2]])
    return return_list

def getNetworkListTimeAfter(time_after): # 返回某个时间之后有更新的节点列表
    global networkList
    return_list = []    #   ['id0','time1','hash2',latency3]
    for key_i, value_i in reversed(networkList.items()):  # 按插入时间倒序，即从新到旧
        if value_i[1] >= time_after: #   时间符合
            return_list.append([key_i,value_i[0],value_i[1],value_i[3]])
        else:   # 搜索结束
            break
    return return_list

def networkListRequestAfterHandler(data):   # 对方请求某个时间后更新的节点，同时支持Node类型筛选
    global networkList
    if 'fromtime' in data:
        return_list = getNetworkListTimeAfter(data['fromtime'])
    if 'nodetype' in data:
        nodeType = data['nodetype']
        return_list = [i for i in return_list if nodeType in i[3]['role'] ] 
    return return_list


def genNodeListForClients():    # 为客户端生成简化的节点列表
    global networkList
    cnt=0;return_list=[]
    return_list = []    #   ['id0','time1','hash']
    for key_i, value_i in reversed(networkList.items()):  # 按插入时间倒序，即从新到旧
        if 'client' in value_i[2]['role']:
            continue
        if cnt<5: #   时间符合   # ID, TIME, ADDR, ROLE, REPORT_LATENCY
            return_list.append([key_i,value_i[0],value_i[2]['addr'],value_i[2]['role'],value_i[3]]);cnt+=1
        else:   # 搜索结束
            break
    return return_list

def updateNodeInfoByData(data,latency = False): # 根据Data包更新节点
    global networkList
    if data['id'] not in networkList:   # 新建节点
        networkList[data['id']] = [data['time'],data['hash'],data['data'],False]
    else:   # 更新节点
        if data['hash']!= networkList[data['id']][1]:   # hash不同
            if data['time']>networkList[data['id']][0]: # 更加新
                networkList[data['id']] = [data['time'],data['hash'],data['data'],networkList[data['id']][3]]
        else:   # hash相同
            if data['time']>networkList[data['id']][0]: 
                networkList[data['id']][0] = data['time']
    if latency:
        networkList[data['id']][3] = latency * 0.6 + networkList[data['id']][3] * 0.4 if networkList[data['id']][3] else latency

def networkReportHandler(data,addr):    # 当接收到一个分布式网络信息包时
    return_data = {}
    if 'from' in data:
        if 'data' in data['from']:
            updateNodeInfoByData(data['from'])
    data = data['data']
    #   Data
    if 'data' in data:  # 完整节点信息字段，先更新自身
        updateNetworkList(data['data'])
    #   Report
    if 'report' in data:    # 对方汇报的本机可能感兴趣的节点
        return_data['request'] = diffNetworkList(data['report'])   # 找出可以向对方请求的节点
    #   Request
    if 'request' in data:   # 对方有Data请求
        return_data['data'] = getNetworkListDataHandler(data['request']) # 对方需要的节点数据
    if 'fromtime' in data: # 对方需要本机在某个时间点后有变动的节点信息
        return_data['report'] = networkListRequestAfterHandler(data['aftertime']) # 对方需要的节点数据

    #   构建返回数据包
    if return_data:
        UDPSendHandler({
            "from":{"id":config['id']},
            "action":"networkreport",
            "data":return_data
        },addr)
    return True

def networkBroadcast(fromtime=time.time()-1800): #   定期广播数据包
    #   上报Data
    target_package = {
        "from":fillFromData(),
        "action":"networkreport",
        "data":{
            "data":genConnectedNodeInfo(),  # 负责的客户端
            "report":networkListRequestAfterHandler({"fromtime":fromtime}), # 近期更新
        }
    }
    cnt = 0
    for node in reversed(networkList):  # 最近联系的节点
        for addr in node[2]['addr']:
            UDPSendHandler(target_package,addr)
        cnt+=1
    if cnt*4>len(networkList):
        return True


### 单列客户端列表

clientList = {} # 'id' --> 'time0','hash1','data2'

def updateClientList(target_list):    # 拥有data，更新clientList
    global networkList
    global clientList
    for each in target_list:    # target_list: [['id0','time1','hash2','data3']]
        if each[0] in clientList:  # 存在ID
            if each[2] != clientList[each[0]][1]:  # hash不同
                if each[1]>clientList[each[0]][0]: # 存在新的数据，更新 clientList
                    clientList[each[0]]={[each[1],each[2],each[3]]}
            else:   # hash相同，更新时间
                networkList[each[0]][0] = max(networkList[each[0]][0], each[1])
        else:   # 不存在ID，新建
            networkList[each[0]] = [each[1],each[2],each[3]]
    return True

### 

def getCertNode():   # 从预设列表获取部分服务节点信息
    my_resolver = dns.resolver.Resolver(configure=False)
    my_resolver.nameservers = [ '223.5.5.5', '119.29.29.29',
                    '2400:3200::1', '2001:4860:4860::8844' ]
    for addr in certNodeList:
        if isIP(addr[0]):
            sendUDPDiscover((addr[0],addr[1]))
        else:
            v4 = my_resolver.resolve(addr[0],"A", raise_on_no_answer=False).rrset
            if v4:
                for ip in v4:
                    sendUDPDiscover((str(ip),addr[1]))
            v6 = my_resolver.resolve(addr[0],"AAAA", raise_on_no_answer=False).rrset
            if v6:
                for ip in v6:
                    sendUDPDiscover((str(ip),addr[1]))
    return True

def sendUDPDiscover(addr):
    UDPSendHandler({
        'from':fillFrom(),
        'action':'userdiscover',
        'event':newEvent(),
    },addr)

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
    token = ''.join(random.sample(string.ascii_letters + string.digits, 16))
    authorizedToken[nodeid] = token # Expired time?
    return token

#### 终端设备连接支持
forwardList = {}    # 中转节点
commandList = {}    # 命令列表
deviceStatus = {}
def deviceSendHandler(data, id,conn = False): # 发送数据到设备
    print("deviceSendHandler ",id," ",conn)
    if not conn:    # 未指定连接
        conn = findConnectionByID(id)
        if conn:    # 已有稳定连接
            if id in forwardList:   # 已建立中转
                forwardID = forwardList[id]
                print("在中转列表，中转ID ",forwardID)
                forward_data={}
                forward_data['data'] = data
                forward_data['from'] = data['from']
                forward_data['to'] = data['to']
                forward_data['event'] = data['event']
                forward_data['action'] = 'forward'
                tcpSendHandler(forward_data,socket=conn)
                return True
            print("直接发送 ",conn)
            tcpSendHandler(data,socket=conn)
            return True
        return False
    else:   # 已指定连接
        if id in forwardList:   # 已建立中转
            forward_data={}
            forward_data['data'] = data
            forward_data['from'] = data['from']
            forward_data['to'] = data['to']
            forward_data['event'] = data['event']
            forward_data['action'] = 'forward'
            tcpSendHandler(forward_data,socket=conn)
            return True
        else:
            tcpSendHandler(data,socket=conn)
            return True
def checkIDConnection(device_id,logger=logInfo):   # 检查是否与某ID建立了连接
    conn = findConnectionByID(device_id)
    if conn:
        if device_id in forwardList:
            forward_id = forwardList[device_id]
            logger("已与目标节点建立中转连接，中转节点"+forward_id)
            return conn
        logger("找到"+device_id+"对应的直接连接")
        return conn
    if device_id in forwardList:
        forward_id = forwardList[device_id]
        conn = findConnectionByID(forward_id)
        if conn:
            logger("已与目标节点建立中转连接，中转节点"+forward_id)
            return conn
    logger(device_id+"尚未建立连接")
    return False

def userEstablishHandler(id,logger=logInfo):   # 向目标设备建立（直接或间接的TCP连接）
    global forwardList
    conn =  checkIDConnection(id)
    if conn:
        return True
    if id not in networkList:
        logger("networkList中找不到"+id)
        return False    # 找不到ID
    if 'addr' in networkList[id][2] and networkList[id][2]['addr']:  # 尝试建立直接连接
        for i in networkList[id][2]['addr']:
            logger("尝试建立连接 "+str(i))
            conn = tcpConnectHandler(i)
            if conn:
                logger("建立了直接连接，对方地址为 "+str(i))
                getDeviceInfo(id,conn = conn,logger=logInfo)
                return True
    if 'forwarder' in networkList[id][2]:   # 尝试联系中转节点
        for i in networkList[id][2]['forwarder']:
            logger("尝试联系中转节点"+str(i[0]))
            if i[0] in networkList: # 服务节点ID在本机获知范围内
                for j in networkList[i[0]][2]['addr']:    # 依次遍历addr
                    conn = tcpConnectHandler(addr=j,timeout=2)   # 这里先阻塞连接吧，也可以在连接建立那写回调处理
                    if conn:    # 后续可加上双向确认
                        forwardList[id] = i[0]
                        logger("与中转节点建立了连接，对方地址为 "+str(j))
                        getDeviceInfo(id,conn = conn,logger=logInfo)
                        return True
            else:   # 使用节点提供的地址
                for j in i[1]:
                    conn = tcpConnectHandler(addr=j,timeout=2)   # 这里先阻塞连接吧，也可以在连接建立那写回调处理
                    if conn:
                        forwardList[id] = i[0]
                        logger("与中转节点建立了连接，对方地址为 "+str(j))
                        getDeviceInfo(id,conn = conn,logger=logInfo)
                        return True
    return False

def getDeviceInfo(id,conn=False,logger=logInfo):  # 获取节点信息，如命令列表 系统信息等，首先需要建立连接
    logger("getDeviceInfo"+id+str(conn))
    if not conn:
        conn = checkIDConnection(id)   # 无连接
        if not conn:
            return False
    deviceSendHandler({
        'from':fillFrom(),
        'to':{"id":id},
        'action':'commandlist',
        'event':newEvent(),
        'data':{}
    },id,conn=conn)
    deviceSendHandler({
        'from':fillFrom(),
        'to':{"id":id},
        'action':'command',
        'event':newEvent(),
        'data':{'command':'status'}
    },id,conn=conn)

def sendDeviceCommand(id,command,**kw): # 给设备发送命令
    if not checkIDConnection(id):   # 无连接
        return False
    kw['command'] = command
    deviceSendHandler({
        'from':fillFrom(),
        'to':{"id":id},
        'action':'command',
        'event':newEvent(),
        'data':kw
    },id)

### 终端设备命令及数据处理

def deviceDataHandler(data,addr):   # 获得了终端返回的数据，处理返回数据的函数
    logGUIWindow("事件"+data['event']+"返回数据为 "+str(data['data']))
    if "status" in data['data']:
        if data['from']['id'] not in deviceStatus:
            deviceStatus[data['from']['id']] = {}
        for k,v in data['data']["status"].items():
            deviceStatus[data['from']['id']][k] = v
    return True

externalLogWindow = logInfo
def logGUIWindow(info):
    global externalLogWindow
    externalLogWindow(info)
def changeExternalLogWindow(data):
    global externalLogWindow
    externalLogWindow = data


### TCP连接管理模块

tcpNodeList = {  # 建立了TCP连接的节点（ID索引）
#   'id':{  #   更多的信息从 reportedNodeList 获取
#       'status': None, direct, forward, disconnected  nw   w   n  nnnnnnnnnnnnnnnnnn  
#       'addr': []  #连接的地址
#   }
}   
tcpPool = { } # TCP连接池，addr --> socket conn（Addr索引）
addrID = { }  # addr --> ID

def addAddrSocket(addr,conn):   # 建立地址和连接的映射关系
    global tcpPool
    if addr in tcpPool:
        if not tcpPool[addr]._closed:
            tcpPool[addr] = conn
        else:
            print("该地址已存在连接",tcpPool[addr],conn)
            return False
    else:
        tcpPool[addr] = conn
    return True

def getAddrSocket(addr):    # 根据地址，获取已经建立的连接
    global tcpPool
    print("此时，TCP连接池有",tcpPool)
    print("获取Socket根据地址",addr)
    if addr in tcpPool:
        print(tcpPool[addr])
        if not tcpPool[addr]._closed:
            print("找到地址对应的连接",addr,tcpPool[addr])
        return tcpPool[addr]
    return False

def delAddrSocket(addr):    # 连接失效了，从已连接地址中删除，同时查找对应的ID，也从中删除
    global tcpPool
    global addrID
    if addr in tcpPool: # 从TCP连接池中删除
        if not tcpPool[addr]._closed:   # 关闭连接
            tcpPool[addr].close()
        tcpPool.pop(addr)
    else:
        return False
    if addr in addrID:  # 同时从ID映射中更改状态
        nodeid = addrID.pop(addr)
        lostStableConnectionNode(nodeid)
        updateNodeAddr(nodeid,addr,action='lostconnection')
    return True

def linkAddrID(addr,id):    # 当确认了已连接的地址对应的ID时
    global addrID
    addrID[addr]=id
    return True

def unlinkAddrID(addr,id):  # 连接丢失，同时修改对应ID的连接状态
    global addrID
    nodeid = addrID.pop(addr)
    updateNodeAddr(nodeid,addr,action='lostconnection')
    return True

def findConnectionByID(id): # 查找ID和Socket的对应关系
    if id not in tcpNodeList:
        return False
    for addr in tcpNodeList[id]['addr']:
        conn = getAddrSocket(addr)
        if conn:
            return conn
    if "addr" in networkList[id][2]:
        for addr in networkList[id][2]['addr']:  # 查找对应地址  MOD
            conn = getAddrSocket(addr)
            if conn:
                return conn
    if tcpNodeList[id]['status'] =='forward':   # 需要转发时
        return False
    return False

def updateNodeAddr(nodeid,addr,action=None,score=None):    # 更新某地址对应的连接状态
    if action=='receivedata':   # 收到数据包，动态更新评分，同时可能是第一次收到来自该节点的数据包，那么将节点和连接关联起来
        if nodeid not in tcpNodeList:
            tcpNodeList[nodeid]={'status':'connected','grade':False}
        if 'addr' not in tcpNodeList[nodeid]:  # 将节点和连接关联
            tcpNodeList[nodeid]['addr'] = {
                addr : {'status':None,'score':None,'time':None}
            }
            addrID[addr] = nodeid
        if addr not in tcpNodeList[nodeid]['addr']:  # 将节点和连接关联
            tcpNodeList[nodeid]['addr'][addr] = {'status':None,'score':None,'time':None}
            addrID[addr] = nodeid
        if score:   # 更新评分
            tcpNodeList[nodeid]['addr'][addr]['score'] = score*0.6 + tcpNodeList[nodeid]['addr'][addr]['score']*0.4
            tcpNodeList[nodeid]['score'] = score*0.6 + tcpNodeList[nodeid]['score'] *0.4
        tcpNodeList[nodeid]['addr'][addr]['time'] = time.time()
        return True
    if action=='newconnection': # 接受了新的连接
        if nodeid not in tcpNodeList:
            return False
        if 'addr' not in tcpNodeList[nodeid]:
            tcpNodeList[nodeid]['addr'] = {
                addr : {'status':None,'score':None,'time':None}
            }
        if addr not in tcpNodeList[nodeid]['addr']:
            tcpNodeList[nodeid]['addr'][addr] = {'status':None,'score':None,'time':None}
        tcpNodeList[nodeid]['addr'][addr]['status'] = 'connected'
        if score:
            tcpNodeList[nodeid]['addr'][addr]['score'] = score*0.6 + tcpNodeList[nodeid]['addr'][addr]['score']*0.4
        tcpNodeList[nodeid]['addr'][addr]['time'] = time.time()
        return True
    if action=='lostconnection':    # 丢失了已建立的连接
        if addr not in tcpNodeList[nodeid]['addr']:
            return False
        tcpNodeList[nodeid]['addr'][addr]['status'] = "disconnected"
        tcpNodeList[nodeid]['addr'][addr]['time'] = time.time()
        return True
    if action=='reportaddress': # 获得报告的地址
        if nodeid not in tcpNodeList:
            return False
        if 'addr' not in tcpNodeList[nodeid]:
            
            tcpNodeList[nodeid]['addr'] = {
                addr : {'status':None,'score':None,'time':time.time()}
            }
            return True
        if addr not in tcpNodeList[nodeid]['addr']:
            tcpNodeList[nodeid]['addr'][addr] = {'status':None,'score':None,'time':time.time()}
            return True
        tcpNodeList[nodeid]['addr']['time'] = time.time()  # 更新最后发现时间
        return False    # 已经存在

def checkEventScore(eventid):   # 检查事件是否存在于本机，如存在，返回连接评分
    timePast = calcEvent(eventid)
    return calcScore(timePast) if timePast else None


### 基础连接支持模块

def UDPRecvHandler():   # UDP接收接口
    global socket_udp
    while True:
        # 接收数据:
        rawdata, addr = socket_udp.recvfrom(65507)
        logInfo('收到来自 %s:%s. 的 UDP 数据包' % addr)
        # 解码到dict
        try:
            data = decryptData(rawdata)
            if 'action' not in data:
                continue
        except Exception as e:
            logErr("解码UDP包错误"+repr(e))

        # in case wait for further package
        if data['from']['id'] == config['id']:
            continue    # ignore local loop
    
        print(data)
        
        threading.Thread(target=UDPdataHandler, args=(data, addr)).start()

def UDP6RecvHandler():   # UDP接收接口
    global socket_udp6
    while True:
        # 接收数据:
        rawdata, addr = socket_udp6.recvfrom(65507)
        if addr[0].startswith('::ffff:'):   # IPv4在IPv6中的映射地址
            addr = addr[0][7:],addr[1]
        logInfo('收到来自 %s:%s. 的 UDP6 数据包' % addr)
        # 解码到dict
        try:
            data = decryptData(rawdata)
            if 'action' not in data:
                continue
        except Exception as e:
            logErr("解码UDP包错误"+repr(e))

        # in case wait for further package
        if data['from']['id'] == config['id']:
            continue    # ignore local loop
    
        print(data)
        
        threading.Thread(target=UDPdataHandler, args=(data, addr)).start()


def UDPdataHandler(data, addr): # UDP数据包处理函数
    logInfo("UDPdataHandler "+str(addr)+str(data))

    if data['action']=='localdiscover': # 来自同局域网内客户端
        return True 

    if data["action"]=="ackdiscover": # 来自其服务节点的，关于其他节点的信息
        eventID = data['event']
        latency = calcEvent(eventID)    # 这是响应本机请求的
        if 'client' in data['data']:    # 这是客户端节点信息
            if data['data']['client']:
                updateClientList(data['data']['client'])
        if 'nodeList' in data['data']:
            inComingList = data['data']['nodeList']
            if inComingList:
                missingList = []
                for i in inComingList:
                    if i not in networkList:
                        missingList.append(i)
                        UDPSendHandler({
                            "from":{"id":config['id']},
                            "action":"networkreport",
                            "data":{
                                'request':missingList
                            }
                        },addr)
        if latency:
            updateNodeInfoByData(data['from'],latency)
            return True
        else:   #   丢弃这个包
            return False    

    if data["action"] == 'networkreport':   # 网络信息交换数据包
        return networkReportHandler(data,addr)

    #   discover/ping 都可测试可达，不过ping并不关心节点的详细信息
    if data["action"] == "ping":  # 对于Client，返回Pong即可，对于Node，说明可能是Client收到了discover
        UDPSendHandler({
            'from': fillFrom(),
            'action': 'pong',
            'event': data['event'],
        },addr)
        return True
    if data["action"] == "pong":  # 可能获得了新的可达节点
        eventID = data['event']
        latency = calcEvent(eventID)    # 这是响应本机请求的
        if latency:
            if data['from']['id'] in networkList:
                networkList[data['from']['id']][3] = latency * 0.6 + networkList[data['from']['id']][3] * 0.4 if networkList[data['from']['id']][3] else latency
            return True
        else:   #   丢弃这个包
            return False
    return True

if os.name=='nt':
    def UDPSendHandler(rawdata,addr,**args):    # UDP发送接口
        logInfo("正在发送UDP包到"+str(addr))
        print(rawdata)
        try:
            data=encryptData(rawdata)
            if os.name == 'nt': # Windows, v4-->udp, v6-->udp6
                if isIP(addr[0])==4:
                    global socket_udp
                    socket_udp.sendto(data,addr)
                else:
                    global socket_udp6
                    socket_udp6.sendto(data,addr)
            return True
        except Exception as e:
            logErr("UDP发送失败"+repr(e))
            return False
else:   # 类Unix系统，v4-->::ff:v4-->udp6, v6-->udp6
    def UDPSendHandler(rawdata,addr,**args):
        global socket_udp6
        try:
            data=encryptData(rawdata)
            if isIP(addr[0])==4:
                addr = ('::ffff:'+addr[0],addr[1])
                socket_udp6.sendto(data,addr)
            else:
                socket_udp6.sendto(data,addr)
            return True
        except Exception as e:
            logErr("UDP发送失败"+repr(e))
            return False

def tcpListenHandler(): # TCP监听处理函数（回应Accept）
    global socket_tcp
    while True:
        try:
            conn, addr = socket_tcp.accept()
            print("Accept new connection from ",addr)
            if addr[0].startswith('::ffff:'):   # IPv4在IPv6中的映射地址
                addr = addr[0][7:],addr[1]
                print("And it's IPv4 is ",addr)
            addAddrSocket(addr,conn)
            threading.Thread(target=tcpRecvHandler,args=(conn,addr,)).start()
        except Exception as e:
            logErr(repr(e))

def tcpRecvHandler(conn,addr):  # TCP接收处理函数（回应某个连接中的Receive）
    conn.setblocking(1)
    while True: # 直到返回空内容，说明连接结束
        try:
            rawdata_len = conn.recv(4)
            if not rawdata_len:
                break
            rawdata_len = struct.unpack('i',rawdata_len)[0]
            print(rawdata_len)
            rawdata = conn.recv(rawdata_len)
            if not rawdata:
                break
            # 解码到dict
            try:
                data = json.loads(rawdata)
                if 'action' not in data:
                    continue
            except Exception as e:
                logErr(repr(e))
                break
            threading.Thread(target=tcpDataHandler,args=(data,addr,)).start()
        except Exception as e:   # conn reset
            print("ERROR: from tcpRecvHandler ",addr,repr(e))
            break
    delAddrSocket(addr)
    print("Lost Connection from ",addr)

def tcpDataHandler(data,addr):  # TCP数据包处理函数
    logInfo("收到了一个TCP数据包"+str(addr)+str(data['from']['id'])+str(data['action']))

    updateNodeAddr(data['from']['id'],addr,'receivedata',score=checkEventScore(data['event'] if 'event'in data else None))
    if data['action'] == 'ping':    #简单的ping，无需关心
        msg = {
            "action": "pong",
            "from": fillFrom(),
            "event":data['event'],
        }
        tcpSendHandler(msg,addr=addr)
        return True
    
    if data['action'] == 'pong':    #说明可达
        return True # 前面已计算事件，无需进一步处理

    if data['action'] == 'establish':   # 建立稳定连接，例如需要认证，返回token
        token = genAuthorizedToken(data['from']['id'])
        tcpSendHandler({
            "action": "ackestablish",
            "from": fillFrom(),
            "event":data['event'],
            'data':{'token':token}
        },addr=addr)
        return True

    if data['action'] == 'ackestablish':    # 获得了来自服务节点的认证
        updateStableConnectionNode(data['from']['id'],data['data']['token'])
        return True

    if data['action'] == 'ackcommandlist':  # 获得设备的命令列表
        commandList[data['from']['id']] = data['data']
        logGUIWindow("收到命令列表，该节点支持操作 "+str(list(commandList[data['from']['id']].keys())))
        return True # 这里主动或被动更新
    
    if data['action'] == 'ackcommand':  # 获得设备的命令结果
        deviceDataHandler(data,addr)
        return True

    if data['action'] == 'forwardfail':  # 获得设备的命令结果
        logGUIWindow("通信失败：中转节点无法到达目标终端节点")
        return True


def tcpConnectHandler(addr,timeout=5):  # 新建TCP连接 处理函数
    if getAddrSocket(addr):
        print("Found existing connection on ",addr)
        return getAddrSocket(addr)
    try:
        print("Try connecting ",addr)
        conn = socket.create_connection(addr,timeout)  #(address[, timeout[, source_address]])
    #   ssl.wrap_socket
    except Exception as e:
        print(repr(e))
        return False
    addAddrSocket(addr,conn)
    print("Connected to ",addr,conn)
    threading.Thread(target=tcpRecvHandler,args=(conn,addr,)).start()
    return conn


def tcpSendHandler(rawdata,id=None,addr=None,socket=None):  # 输入dict，目标ID|目标地址|目标Socket
    conn = None
    if socket:  #指定Socket
        conn = socket
    elif addr:  #指定二元组
        conn = getAddrSocket(addr)
    if not conn:
        if id:  #按照ID查找
            if not conn:
                # 查找已建立的连接，因为tcpSendHandler不负责建立连接
                conn = findConnectionByID(id)
    if not conn:
        logErr("无法找到对应的有效连接"+str(id)+str(addr)+str(socket))
    try:
        print("TCP发送到",conn.getpeername(),rawdata)
        #Encrypt Dict
        data=json.dumps(rawdata).encode()
        conn.sendall(struct.pack('i',len(data)))
        conn.sendall(data)
        return True
    except Exception as e:
        print(repr(e))
        return False

### 客户端功能函数

### 初始化设备，绑定Socket

initNode()

if os.name == 'nt': # Windows，UDP需要分别监听v4和v6
    socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket_udp.bind(('',DEFAULT_SERVER_PORT))
    socket_udp.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
    threading.Thread(target=UDPRecvHandler).start()
    socket_udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    socket_udp6.bind(('::',DEFAULT_SERVER_PORT))
    threading.Thread(target=UDP6RecvHandler).start()
else:   # Linux中，UDP6监听::，同时注意映射地址
    socket_udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    socket_udp6.bind(('::',DEFAULT_SERVER_PORT))
    threading.Thread(target=UDP6RecvHandler).start()


tcp_addr = ('',DEFAULT_SERVER_PORT)
if socket.has_dualstack_ipv6():
    print("has_dualstack_ipv6")
    socket_tcp = socket.create_server(tcp_addr, family=socket.AF_INET6, dualstack_ipv6=True)
else:
    print("TCP4 only")
    socket_tcp = socket.create_server(tcp_addr)
try:
    socket_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
except:
    pass
try:
    socket_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
except:
    pass
socket_tcp.listen()
thread_tcp = threading.Thread(target=tcpListenHandler).start()


### 主函数入口

getCertNode()

