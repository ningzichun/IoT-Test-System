import socket
import threading
import socket
import threading
import time
import psutil
import json
import pickle
import ipaddress
import random
import struct
import os
import queue
import string
### 服务节点程序 reBuild_220501

config= {}
DEFAULT_SERVER_PORT = 20020

import dns.resolver
certNodeList = [("iot.mrning.com",20020)]   # 预设节点列表 [(domain|ip,port),addr2]


def initNode(): # 初始化节点配置
    global config
    try:    # 尝试获取本地的配置文件
        with open('./node.json','r',encoding='utf-8') as f:
            config = json.load(f)
    except Exception:
        pass

    # 填充默认值
    if "id" not in config:
        config["id"]=genID()

    if "role" not in config:    # 默认的节点参与的角色
        config["role"]=[
            "forward",
            "storage",
            "analyze",
            "certify"
        ]

    if "name" not in config:    # 使用hostname填充友好名称
        config["name"]=socket.gethostname()

    if "config" not in config:
        config["config"] = {"SERVER_IP":[],"SERVER_PORT":None}
    # save config file
    with open('./node.json','w') as f:
        f.write(json.dumps(config))
        f.close()
    
    if config["config"]["SERVER_IP"]:
        config['addr'] = []
        for ip in config["config"]["SERVER_IP"]:
            config['addr'].append((ip,config["config"]["SERVER_PORT"]))
    if "addr" not in config:    # 尝试使用公网地址填充
        config['addr'] = [(i,DEFAULT_SERVER_PORT) for i in getGlobalIPs()]
    
    logInfo("节点初始化完成\n"+str(config))

def genID():    # 生成本机ID
    import uuid
    return str(uuid.uuid1())

def fillFrom(): # 填充from项
    fromDict={
        "id":config["id"],
        "role": config["role"],
        "name": config["name"],
    }
    if config['addr']:
        fromDict["addr"] = config["addr"]
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

def getInterface(): # 获取网卡信息
    net_if_addrs = psutil.net_if_addrs()
    interfaces = []
    for k in net_if_addrs:
        # a new net_interface
        netif = {'name': k}
        for v in net_if_addrs[k]:   #snicaddr(family=<AddressFamily.AF_LINK: -1>, address='AA-BB-', netmask=None, broadcast=None, ptp=None)
            # check address
            try:
                if v[0] == psutil.AF_LINK:  #MAC
                    netif['mac'] = v[1]
                elif v[0] == socket.AddressFamily.AF_INET:  #IPv4
                    v4 = ipaddress.IPv4Address(v[1])
                    if v4.is_global:
                        if "ipv4" not in netif:
                            netif["ipv4"] = []
                        netif["ipv4"].append({
                            'ip': v[1],
                            'type': 'global',
                        })
                    elif v4.is_private:
                        if v4.is_link_local or v4.is_loopback or v4.is_reserved:
                            continue
                        if "ipv4" not in netif:
                            netif["ipv4"] = []
                        netif["ipv4"].append({
                            'ip': v[1],
                            'type': 'private',
                        })
                elif v[0] == socket.AddressFamily.AF_INET6: #IPv6
                    v6 = ipaddress.IPv6Address(v[1])
                    if v6.is_global:
                        if "ipv6" not in netif:
                            netif["ipv6"] = []
                        netif["ipv6"].append({
                            'ip': v[1],
                            'type': 'global',
                        })
            except Exception:
                pass
        if "ipv4" in netif or "ipv6" in netif:
            interfaces.append(netif)
    return interfaces

def getIPs():   # 从网卡信息中读取IP
    interfaces = getInterface()
    IPs={"global":[],"private":[]}
    for i in interfaces:
        if "ipv4" in i:
            for v4 in i["ipv4"]:
                if v4["type"] == "global":
                    IPs["global"].append({
                        "ip": v4["ip"],
                        "name": i["name"],
                    })
                else:
                    IPs["private"].append({
                        "ip": v4["ip"],
                        "name": i["name"],
                    })
        if "ipv6" in i:
            for v6 in i["ipv6"]:
                if v6["type"] == "global":
                    IPs["global"].append({
                        "ip": v6["ip"],
                        "name": i["name"],
                    })
    return IPs

def getGlobalIPs(): # 获取全局IP地址
    IPs = getIPs()['global']
    globalIPs = [i['ip'] for i in IPs]
    return globalIPs

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



#   分布式节点获取，服务节点版本

#   Forwarder： 围绕Client,Storage，可为其提供转发服务
#   Archiever:  观察和记录网络

#   节点间互相沟通，致力于更新完整网络（区别于DHT，更类似于IPFS）
#   根据可达性进行优先级区分，比如主动发送信息，主动询问信息，被动接收记录信息

#   格式：ID, 来自Client最后遇见时间，以及当时状态的Hash，以此判定是否需要更新
#   通用的网络状态数据包包含三个部分：Report 上报本机具有的可引起重视的ID, Time（更新为最新）, Hash, 比如近期有更新的节点，或全部节点
#   Request 向这台机器请求某个ID的数据，比如在Report中发现了新的或感兴趣的节点，但没用Data
#   Data 预先提供某个节点更新了的Data（比如是Client的负责节点，那么就有相对的义务），以及上次Request中的请求，同时捎带）


networkList = { # 对于Python3.6+，Dict插入有序；Python3.8支持reversed返回key的iter
    #   'id':   'time0','hash1','data2','latency3'
}

UDPPingIDQueue = queue.Queue()
UDPDiscoverQueue = queue.Queue()

def UDPPingID():
    while True:
        target_id = UDPPingIDQueue.get()
        if target_id in networkList:
            eventID = newEvent()
            for iterAddr in networkList[target_id][2]['addr']:
                UDPSendHandler({
                "action": "ping",
                "from": fillFromData(),
                "event":eventID
            },iterAddr)

def UDPDiscoverID():
    while True:
        target_id = UDPDiscoverQueue.get()
        if target_id in networkList:
            eventID = newEvent()
            for iterAddr in networkList[target_id][2]['addr']:
                UDPSendHandler({
                "action": "nodediscover",
                "from": fillFromData(),
                "event":eventID
            },iterAddr)


def calcHash(data):
    return hash(str(data))


def genConnectedNodeInfo(): # 获取已连接客户端节点
    print(stableConnectionList)
    print(networkList)
    return_list = []
    for k in stableConnectionList.keys():    # id, time, hash, data
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
    for each in target_list:    # target_list: [['id0','time1','hash2','data3']]
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
    return cnt

def getNetworkListDataHandler(target_list): # 获取要求的节点信息列表
    print("getNetworkListDataHandler:",target_list)
    return_list = []
    for i in target_list:
        if i in networkList:   # [['id0','time1','hash2','data3']]
            return_list.append([i,networkList[i][0],networkList[i][1],networkList[i][2]])
    return return_list

def getNetworkListTimeAfter(time_after): # 返回某个时间之后有更新的节点列表
    return_list = []    #   ['id0','time1','hash2',latency3]
    for key_i, value_i in reversed(networkList.items()):  # 按插入时间倒序，即从新到旧
        if value_i[1] >= time_after: #   时间符合
            return_list.append([key_i,value_i[0],value_i[1],value_i[3]])
        else:   # 搜索结束
            break
    return return_list

def networkListRequestAfterHandler(data):   # 对方请求某个时间后更新的节点，同时支持Node类型筛选
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
    print("收到节点信息",data['id'])
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
    print(networkList.keys())
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
    if 'timefilter' in data: # 对方需要本机在某个时间点后有变动的节点信息
        return_data['report'] = networkListRequestAfterHandler(data['timefilter']) # 对方需要的节点数据
    print(return_data)
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
        if 'addr' in node[2]:
            for addr in node[2]['addr']:
                UDPSendHandler(target_package,addr)
        cnt+=1
    if cnt*4>len(networkList):
        return True

def networkBroadcastDaemon():
    time.sleep(100)
    networkBroadcast()
    time.sleep(1700)

def getCertNode():   # 从预设列表获取部分服务节点信息
    my_resolver = dns.resolver.Resolver()
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
        'from':fillFromData(),
        'action':'nodediscover',
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
            print("该地址已存在连接",tcpPool[addr])
            return False
    else:
        tcpPool[addr] = conn
    return True

def getAddrSocket(addr):    # 根据地址，获取已经建立的连接
    global tcpPool
    # print("此时，TCP连接池有",tcpPool)
    # print("获取Socket根据地址",addr)
    if addr in tcpPool:
        # print(tcpPool[addr])
        if tcpPool[addr]._closed:
            delAddrSocket(addr)
            return False
        logInfo("找到地址对应的连接",addr)
        return tcpPool[addr]
    return False

def delAddrSocket(addr):    # 连接失效了，从已连接地址中删除，同时查找对应的ID，也从中删除
    global tcpPool
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
    global tcpPool
    addrID[addr]=id
    return True

def unlinkAddrID(addr,id):  # 连接丢失，同时修改对应ID的连接状态
    global tcpPool
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
    if addr in networkList[id][2]:  # 查找对应地址  MOD
        conn = getAddrSocket(addr)
        if conn:
            return conn
    if tcpNodeList[id]['status'] =='forward':   # 需要转发时
        return False
    return False
def updateNodeAddr(nodeid,addr,action=None,score=None):    # 更新某地址对应的连接状态
    global tcpNodeList
    global addrID
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
            tcpNodeList[nodeid]={'status':'connected','grade':False}
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
        # 解码到dict
        try:
            data = decryptData(rawdata)
            if 'action' not in data:
                continue
            logInfo('收到来自',addr,'的 UDP 数据包，其操作为',data['action'])
        except Exception as e:
            logErr("解码UDP包错误"+repr(e))

        # in case wait for further package
        if data['from']['id'] == config['id']:
            continue    # ignore local loop
    
        # print(data)
        
        threading.Thread(target=UDPdataHandler, args=(data, addr)).start()

def UDP6RecvHandler():   # UDP接收接口
    global socket_udp6
    while True:
        # 接收数据:
        rawdata, addr = socket_udp6.recvfrom(65507)
        if addr[0].startswith('::ffff:'):   # IPv4在IPv6中的映射地址
            addr = addr[0][7:],addr[1]
        # 解码到dict
        try:
            data = decryptData(rawdata)
            if 'action' not in data:
                continue
            logInfo('收到来自',addr,'的 UDP 数据包，其操作为',data['action'])
        except Exception as e:
            logErr("解码UDP包错误"+repr(e))

        # in case wait for further package
        if data['from']['id'] == config['id']:
            continue    # ignore local loop
    
        # print(data)
        
        threading.Thread(target=UDPdataHandler, args=(data, addr)).start()


def UDPdataHandler(data, addr): # UDP数据包处理函数
    logInfo("UDPdataHandler "+str(addr)+str(data))
    if data["action"]=="clientdiscover":   # 来自客户端的发现请求
        updateNodeInfoByData(data['from'])  # 记录下信息
        UDPSendHandler({
                "action": "ackdiscover",
                "from": fillFromData(),
                "event":data['event'],
                "data":{
                    "nodeList":genNodeListForClients()
                }
            },addr)
        return True 
    if data['action']=='localdiscover': # 来自同局域网内客户端
        UDPSendHandler({
                "action": "ackdiscover",
                "from": fillFromData(),
                "event":data['event'],
                "data":{
                    "nodeList":genNodeListForClients()
                }
            },(addr[0],DEFAULT_SERVER_PORT))
        return True 

    if data["action"]=="nodediscover":   # 来自服务节点的发现请求
        updateNodeInfoByData(data['from'])  # 记录下信息
        # 确认双向可达，汇报自身状态，返回负责客户端
        UDPSendHandler({
            'from': fillFromData(),
            'action': 'ackdiscover',
            'event': data['event'],
            'data':{'client':genConnectedNodeInfo(),
                    'nodeList':list(networkList.keys()),
                    }
        },addr)
        UDPSendHandler({
            'from': fillFrom(),
            'action':'ping',
            'event': newEvent(),
        },addr)
        return True
    if data["action"]=="userdiscover":  # 来自用户的发现请求
        UDPSendHandler({
            'from': fillFromData(),
            'action': 'ackdiscover',
            'event': data['event'],
            'data':{'client':genConnectedNodeInfo(),
                    'nodeList':list(networkList.keys()),
                    }
        },addr)
    if data["action"]=="ackdiscover": # 来自其他客户端或服务节点的，关于其他节点的信息
        eventID = data['event']
        latency = calcEvent(eventID)    # 这是响应本机请求的
        if latency:
            if 'nodeList' in data['data']:  # 返回了节点列表
                missingList = []
                for i in data['data']['nodeList']:
                    if i[0] not in networkList:
                        missingList.append(i)
            UDPSendHandler({
                "from":{"id":config['id']},
                "action":"networkreport",
                "data":{
                    'request':missingList
                }
            },addr)
            # 还有节点自身的信息
            updateNodeInfoByData(data['from'],latency)
            return True
        else:   #   丢弃这个包
            return False    
    if data["action"]=="discover":    # 收到发现请求（对于Client，只会接收本地的），可能来自Client, 或其他角色
        if 'data' in data['from']:  # 包含完整的对端信息 
            updateNodeInfoByData(data['from'])  # 记录下信息
        if 'client' in data['from']['data']['role']:    # 来自客户端的广播，协助其发现网络
            UDPSendHandler({
                "action": "ackdiscover",
                "from": fillFromData(),
                "event":data['event'],
                "data":{
                    "nodeList":genNodeListForClients()
                }
            },addr)
            return True 
        # 非Client节点，那么就记录节点，确认双向可达，汇报自身状态
        UDPSendHandler({
            'from': fillFromData(),
            'action': 'ackdiscover',
            'event': data['event'],
        },addr)
        UDPSendHandler({
            'from': fillFrom(),
            'action':'ping',
            'event': newEvent(),
        },addr)
        return True
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
        logInfo("正在发送UDP包到",str(addr),'其操作为',rawdata['action'])
        # print(rawdata)
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
            raise e
            return False
else:   # 类Unix系统，v4-->::ff:v4-->udp6, v6-->udp6
    def UDPSendHandler(rawdata,addr,**args):
        logInfo("正在发送UDP包到",str(addr),'其操作为',rawdata['action'])
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
            logInfo("接受新TCP连接，来自 "+str(addr))
            if addr[0].startswith('::ffff:'):   # IPv4在IPv6中的映射地址
                addr = addr[0][7:],addr[1]
                logInfo("其对应的IPv4地址为 "+str(addr))
            addAddrSocket(addr,conn)
            threading.Thread(target=tcpRecvHandler,args=(conn,addr,)).start()
        except Exception as e:
            logErr(repr(e))

def tcpRecvHandler(conn,addr):  # TCP接收处理函数（回应某个连接中的Receive）
    while True: # 直到返回空内容，说明连接结束
        try:
            rawdata_len = conn.recv(4)
            if not rawdata_len:
                break
            rawdata_len = struct.unpack('i',rawdata_len)[0]
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
    print("失去TCP连接 "+str(addr))

def tcpDataHandler(data,addr):  # TCP数据包处理函数
    logInfo("收到了一个TCP数据包，来自 "+str(addr)+"，ID "+str(data['from']['id'])+"，操作 "+str(data['action']))
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

    if data['action'] == 'hello':    #返回完整自身信息
        eventID = calcEvent(eventID)
        msg = {
            "action": "ackhello",
            "from": fillFromData(),
            "event":data['event'],
        }
        tcpSendHandler(msg,addr=addr)
        return True
    
    if data['action'] == 'ackhello':    #客户端收到了对方的完整信息
        eventTime = calcEvent(eventID)
        if not eventTime:
            return False
        addNodeFromRemote(data['from']['id'],time.time(),data['from']['data']['role'],eventTime,True)   # TCP可达
        return True

    if data['action'] == 'establish':   # 建立稳定连接，例如需要认证，返回token
        token = genAuthorizedToken(data['from']['id'])
        if 'forwarder' not in data['from']['data']: # 加上本机信息
            data['from']['data']['forwarder'] = [[config['id'],config['addr']]]
        else:
            data['from']['data']['forwarder'].append([config['id'],config['addr']])
        updateStableConnectionNode(data['from']['id'],token)
        updateNodeInfoByData(data['from'])
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

    if data['action'] == 'forward':  # 转发数据包
        conn = findConnectionByID(data['to']['id'])
        if not conn:
            tcpSendHandler({
                "action": "forwardfail",
                "from": fillFrom(),
                "event":data['event'],
            },addr=addr)
            return False
        tcpSendHandler(data['data'],socket = conn)
        return True

    if data["action"]=="command":   # 给设备下指令
        if not checkIncomingEvent(data['from']['id']+data['event']):
            return False    # 已经处理过这个事件了，忽略
        report_data = {
            "from": fillFrom(), 
            "event": data["event"],
            "data": commandHandler(data["data"])
        }
        tcpSendHandler(report_data,addr=addr)

    if data["action"]=="update":    # (来自稳定连接节点的)信息更新
        return False
    
    if data['action'] == 'requeststorage':   # 这里是服务端的代码，说明得对这个客户端进行追踪
        return False

    if data["action"]=="ackcommand":   # 中转数据包
        conn = findConnectionByID(data['to']['id'])
        if not conn:
            tcpSendHandler({
                "action": "forwardfail",
                "from": fillFrom(),
                "event":data['event'],
            },addr=addr)
            return False
        tcpSendHandler(data,socket = conn)
        return True
    if data["action"]=="ackcommandlist":   # 中转数据包
        conn = findConnectionByID(data['to']['id'])
        if not conn:
            tcpSendHandler({
                "action": "forwardfail",
                "from": fillFrom(),
                "event":data['event'],
            },addr=addr)
            return False
        tcpSendHandler(data,socket = conn)
        return True
        
    if data["action"]=="nodemap":   #node节点才会收到
        pass



def tcpConnectHandler(addr,timeout=5):  # 新建TCP连接 处理函数
    if getAddrSocket(addr):
        logInfo("发现已存在的连接 "+str(addr))
        return getAddrSocket(addr)
    try:
        logInfo("尝试连接 "+str(addr))
        conn = socket.create_connection(addr,timeout)  #(address[, timeout[, source_address]])
    #   ssl.wrap_socket
    except Exception as e:
        logErr(repr(e))
        return False
    addAddrSocket(addr,conn)
    logInfo("连接到了 "+str(addr))
    threading.Thread(target=tcpRecvHandler,args=(conn,addr,)).start()
    return True


def tcpSendHandler(rawdata,id=None,addr=None,socket=None):  # 输入dict，目标ID|目标地址|目标Socket
    conn = None
    if socket:  #指定Socket
        conn = socket
    elif addr:  #指定二元组
        conn = getAddrSocket(addr)
    if id:  #按照ID查找
        if not conn:
            # 查找已建立的连接，因为tcpSendHandler不负责建立连接
            conn = findConnectionByID(id)
    if not conn:
        logErr("无法找到对应的有效连接"+str(id)+str(addr)+str(socket))
    try:
        logInfo("正在发送TCP数据包到"+str(conn.getpeername()),"，操作为",rawdata['action'])
        #Encrypt Dict
        data=json.dumps(rawdata).encode()
        conn.sendall(struct.pack('i',len(data)))
        conn.sendall(data)
        return True
    except Exception as e:
        print(repr(e))
        return False

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

thread_tcp = threading.Thread(target=networkBroadcastDaemon).start()