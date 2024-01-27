#!/usr/bin/env python3

import base64
import datetime
import hashlib
import json
import operator
import os
import random
from unicodedata import name
import requests
import sys
import time
from cls import IpAddress
from cls import IsValid
from cls import LocalFile
from cls import ListFile
from cls import NetFile
from cls import PingIP
from cls import StrText
from cls import SubConvert

# 获取传递的参数
try:
    #0表示文件名，1后面都是参数 0.py, 1, 2, 3
    menu = sys.argv[1:][0]
    if(len(sys.argv[1:]) > 1):
        cid = sys.argv[1:][1]
except:
    menu = 'init'
print('menu: ' + menu)

# onenode = '{"name":"\ud83c\uddef\ud83c\uddf5-\u65e5\u672c-146.56.156.90","server":"146.56.156.90","port":443,"alterId":0,"cipher":"auto","network":"ws","type":"none","tls":"tls","uuid":"6093eefb-7ab6-41df-aba0-d5fa58147e10","sni":null,"host":"146.56.156.90","path":"/reffs7y26g0ua"}'
# SubConvert.v2ray_vmess_to_clash(onenode)
# SubConvert.check_url_v2ray_vmess(onenode)

# menu = 'expire'
# menu = 'update'
# menu = 'optnode'
# menu = 'allclash'
# 配置信息和同步本地需要更新的资源文件
# resurl = "http://127.0.0.1/"
resurl = 'https://aipfs.dns.army/ipns/k51qzi5uqu5dgiinzrr0r5xnq55uhoy6ytf0m1d27z655ha2mvljqyjybrj2xz/'
errnode = ''

# 对程序的基本信息进行下载更新，下载IPFS网关信息和过滤列表信息
if(menu == 'init'):
    filename = 'ipfs|expire.txt'
    for i in filename.split('|'):
        try:
            File = NetFile.url_to_str(resurl + '' + i, 360, 360)
            if(len(File) > 10240):
                LocalFile.write_LocalFile('./res/' + i, File.strip('\n')) 
                print('Get-File-is-True:' + resurl + '' + i + ' FileSize:' + str(len(File)))
        except Exception as ex:
            LocalFile.write_LogFile('Main-Line-54-Get-File-is-False:' + resurl + '' + i + '\n' + str(ex))

# 本项取消，下载订阅办的到本地并将其合并到发布的节点，直接进行CID合并发布，软件下载已经取消。
if(menu == 'soft'):
    filename = 'soft/Clash.for.Windows-0.19.0-win.7z|soft/v2rayN-Core.zip'
    for i in filename.split('|'):
        try:
            if(i.find('soft')>-1):
                File = NetFile.url_to_str(resurl + '' + i, 240, 300)
                LocalFile.write_LocalFile('./o/' + i, File.strip('\n'))
                print('成功下载：' + i + ', FileSize:' + str(len(File)) + '。')
            else:
                File = NetFile.url_to_str(resurl + '' + i, 240, 120)
                if(len(File) > 1000):
                    LocalFile.write_LocalFile('./res/' + i, File.strip('\n')) 
                    print('Get-File-is-True:' + resurl + '' + i + ' FileSize:' + str(len(File)))
        except Exception as ex:
            LocalFile.write_LogFile('Main-Line-71-Get-File-is-False:' + resurl + '' + i + '\nException:\n' + str(ex))

# 下载Node.json中的所有Url订阅链接将其合并，生成本地vpei-new.txt，同步至Github后改名为vpei.txt文件
if(menu == 'expire'):
    expires = ''
    errnode = LocalFile.read_LocalFile("./res/errnode.txt")
    netexpire = LocalFile.read_LocalFile("./res/expire.txt")
    # 本地所有失效链接合并去重存储至expires.txt
    allexpire = errnode.strip('\n') + '\n' + netexpire.strip('\n') #+ '\n' + NetFile.url_to_str('https://ql.vmess.com/expire.txt', 240, 300).strip('\n')
    expirecount = len(allexpire.split('\n'))
    print('Get-oldexpire.txt: \n' + str(expirecount))

    # 处理临时数据和网络失效数据中vmess同一IP和端口过滤列表
    fakeip = LocalFile.read_LocalFile("./res/fakeip.txt")
    fakedomain = LocalFile.read_LocalFile("./res/fakedomain.txt")
    ii = 0
    for j in allexpire.split('\n'):
        try:
            ii += 1
            # j = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIvCfh7rwn4e4Lee+juWbvS10dzEuc2FuZmVuMDAxLnBpY3MiLA0KICAiYWRkIjogInR3MS5zYW5mZW4wMDEucGljcyIsDQogICJwb3J0IjogIjQ0MyIsDQogICJpZCI6ICIwNTM4MzAyMi01OTRhLTQ0ZWEtYTE5ZS1jOTcyZjRhMTU0OTIiLA0KICAiYWlkIjogIjAiLA0KICAic2N5IjogImF1dG8iLA0KICAibmV0IjogIndzIiwNCiAgInR5cGUiOiAidm1lc3MiLA0KICAiaG9zdCI6ICIiLA0KICAicGF0aCI6ICJ0dzEuc2FuZmVuMDAxLnBpY3MiLA0KICAidGxzIjogInRscyIsDQogICJzbmkiOiAiIiwNCiAgImFscG4iOiAiIg0KfQ=='
            if(j == ''):
                continue
            if (j.find("vmess://") == 0):
                onenode = SubConvert.check_url_v2ray_vmess(j)
                onenode = base64.b64decode(onenode[8:].encode('utf-8')).decode('utf-8')
            elif (j.find("ss://") == 0):                        
                onenode = SubConvert.url_ss_to_json(j)
            elif (j.find("trojan://") == 0):
                onenode = SubConvert.url_trojan_to_json(j)
            elif (j.find("ssr://") == 0):
                onenode = base64.b64decode(j[6:]).decode('utf-8')
                onenode = onenode.split(':')
                server = onenode.split(':')[0]
                port = onenode.split(':')[1]
                protocol = onenode.split(':')[2]
                cipher = onenode.split(':')[3]
                http_simple = onenode.split(':')[4]
                password = base64.b64decode(onenode.split(':')[3])
                onenode = '{"name": "", "server": "' + server + '", "port": "' + str(port) + '", "protocol": "' + protocol + '", "cipher": "' + cipher + '", "http_simple": "' + http_simple + '", "password": "' + password + '", "type": "ssr"}'
            else:
                # vless://c07fef7d-e8d2-42fe-b977-50e368f18293@104.16.16.255:443?flow=xtls-rprx-direct-udp443&encryption=none&security=tls&sni=vincent-jackson2021.ga&type=ws&host=vincent-jackson2021.ga&path=%2fThe-Great-Awakening_ws
                print('Main-Line-134-已跳过-onenode:\n' + j)
                continue
            if(onenode != ''):
                node = json.loads(onenode)
                server = ''
                port = ''
                password = ''
                if('add' in node.keys()):
                    server = node['add']
                else:
                    server = node['server']
                port = str(node['port'])
                if('password' in node.keys()):
                    password = node['password']
                elif('id' in node.keys()):
                    password = node['id']
                elif('uuid' in node.keys()):
                    password = node['uuid']
                j = server + ':' + port + ':' + password
                if(fakeip.find(j) == -1 and fakedomain.find(j) == -1):
                    if(IsValid.isIP(server) == True):
                        fakeip = fakeip + '\n' + j
                    else:
                        fakedomain = fakedomain + '\n' + j
        except Exception as ex:
            LocalFile.write_LogFile('Main-Line-149-Exception:' + str(ex) + '\nondenode:' + j)
    LocalFile.write_LocalFile('./res/fakeip.txt', fakeip)
    LocalFile.write_LocalFile('./res/fakedomain.txt', fakedomain)
    
# 下载Node.json中的所有Url订阅链接将其合并，生成本地vpei-new.txt，同步至Github后改名为vpei.txt文件
if(menu == 'update'):
    # 读取所有节点到allonenode新记录后面。
    ii = 0
    oldallonenode = ''
    while(ii < 99):
        try:
            filepath = './res/nod-' + str(ii) + '.txt'
            if(os.path.exists(filepath)):
                oldallonenode = oldallonenode + '\n' + base64.b64decode(LocalFile.read_LocalFile(filepath)).decode('utf-8')
                os.remove(filepath)
                ii += 1
            else:
                ii = 99
        except Exception as ex:
            LocalFile.write_LogFile('Main-Line-171-Exception:' + str(ex) + '\nfilepath:' + filepath)
    print('Main-Line-124-Node-Txt1-oldallonenode-size:' + str(len(oldallonenode)) + '')
            
    nodes = LocalFile.read_LocalFile("./res/node.json")
    print('Get-node.json: \n' + str(len(nodes.split('\n'))))
    #sub_link = []
    #for i in range(len(sub_url)):
    #    s_url = sub_url[i]
    nodeurl = ''
    clashnodes = ''
    allonenode = ''
    list1 = nodes.split('\n')
    list1 = ListFile.get_list_sort(list1)
    ii = 0
    iii = 0
    for i in list1:
        ii += 1
        print('\nNodes-List-OneNodeList:\n' + i)
        if(i == ''):
            continue
        else:
            onode = json.loads(i)
            onode_uptime = onode['uptime']
            onode_upmd5 = onode['upmd5']
            onode_upurl = onode['upurl']
            onode_size = onode['size']
        if(nodeurl.find(onode_upurl) == -1):
            try:                
                onode_upurl = onode_upurl.replace('<yyyy>', datetime.datetime.now().strftime('%Y'))
                onode_upurl = onode_upurl.replace('<mm>', datetime.datetime.now().strftime('%m'))
                onode_upurl = onode_upurl.replace('<dd>', datetime.datetime.now().strftime('%d'))
                print('Get node link on sub ' + onode_upurl)
                clashnodes = NetFile.url_to_str(onode_upurl, 240, 120)
                if(clashnodes == ''):
                    nodeurl = nodeurl + '\n' + i
                    continue
                clashnodes = clashnodes.replace(' ','')
                clashnodes = clashnodes.encode('utf-8').decode('utf-8', 'ignore').strip('\n')
                if (clashnodes != '' and onode_upmd5 != hashlib.md5(clashnodes.encode('utf-8')).hexdigest()):
                    onode['upmd5'] = hashlib.md5(clashnodes.encode('utf-8')).hexdigest()
                    if (onode_upurl.find('com/index.html') > -1):
                        onode['uptime'] = (datetime.datetime.now() + datetime.timedelta(days=1096)).strftime("%Y-%m-%d %H:%M:%S")
                    elif (onode_upurl.find('res/vpn') > -1 or onode_upurl.find('o/node') > -1):
                        onode['uptime'] = (datetime.datetime.now() + datetime.timedelta(days=730)).strftime("%Y-%m-%d %H:%M:%S")
                    elif (onode_upurl.find('ipns') > -1 or onode_upurl.find('vpnn') > -1 or onode_upurl.find('com/vpn') > -1):
                        onode['uptime'] = (datetime.datetime.now() + datetime.timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
                    #elif (ii > 115):
                    #    onode['uptime'] = (datetime.datetime.now() + datetime.timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        onode['uptime'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    onode['size'] = len(clashnodes)
                    i = json.dumps(onode)
                    print('UpdateTime:' + onode['uptime'] + ' clashnodes-len:' + str(len(clashnodes)))
                    if(IsValid.isBase64(clashnodes)):
                        clashnodes = StrText.get_str_base64(clashnodes) # Base64格式化
                        clashnodes = base64.b64decode(clashnodes).decode('utf-8')
                        print('Url-All-Nodes-is-Base64:' + clashnodes)
                    else:
                        print('Url-All-Nodes-no-Base64:' + clashnodes)
                    allonenode = ''
                    if (onode['type'] == 'mixed'):
                        allonenode = clashnodes
                    elif (onode['type'] == 'clash'):
                        #- {name: "suo.yt/ssrsub", server: uuus1.liuwei01.tk, port: 443, type: vmess, uuid: 0fab5928-9d70-4666-b351-5debff8a15de, alterId: 0, cipher: auto, tls: true, skip-cert-verify: false, network: ws, ws-path: /liuwei, ws-headers: {Host: uuus1.liuwei01.tk}, udp: true}
                        #- {name: 'dlj.tf/ssrsub', server: 172.99.190.153, port: 8090, type: ss, cipher: aes-256-gcm, password: PCnnH6SQSnfoS27, udp: true}
                        if(clashnodes.find('proxies:') > -1 and clashnodes.find('proxy-groups:') > -1):
                            clashnodes = StrText.get_str_btw(clashnodes, 'proxies:', 'proxy-groups:', 0)
                        elif(clashnodes.find('proxies:') > -1 and clashnodes.find('proxy-groups:') == -1):
                            clashnodes = clashnodes.partition('proxies:')[2]
                        else:
                            clashnodes = ''
                        if(clashnodes != ''):
                            print('Main-Line-167-clashnodes:\n' + clashnodes)
                            clashnodes = clashnodes.replace('\'', '').replace('"', '').replace(' ', '')
                            if(clashnodes.find(',') > -1 and clashnodes.find('{') > -1 and clashnodes.find('}') > -1):
                                # - {……}\n - {……}\n - {……}
                                clashnodes = clashnodes.replace('-{', '{')
                            else:
                                # - …\n…\n…\n - …\n…\n…\n - …\n…\n…\n
                                clashnodes = clashnodes.replace(' ', '')
                                clashnodes = clashnodes.replace('\r', ',').replace('\n', ',')
                                clashnodes = clashnodes.strip('\n').strip('-')
                                clashnodes = clashnodes.replace(',-', '}\n{')
                                clashnodes = clashnodes.replace(',,', ',').replace(',,', ',')
                                clashnodes = '{' + clashnodes + '}'
                            for onenode in clashnodes.split('\n'):
                                try:
                                    allonenode += '\n' + SubConvert.clash_to_all_url(onenode)
                                except Exception as ex:
                                    LocalFile.write_LogFile('Main-Line-205-Exception:' + str(ex) + '\nonenode:\n' + onenode)
                    elif (onode['type'] == 'surge'):
                        try:
                            if(clashnodes.find('[Proxy]') > -1 and clashnodes.find('[Proxy Group]') > -1):
                                clashnodes = StrText.get_str_btw(clashnodes, '[Proxy]', '[Proxy Group]', 0)
                            elif(clashnodes.find('proxies:') > -1 and clashnodes.find('proxy-groups:') == -1):
                                clashnodes = ''
                        except Exception as ex:
                            LocalFile.write_LogFile('Main-Line-225-Exception:' + str(ex) + '\nonenode:\n' + onenode)
                        print('Main-Line-205-clashnodes:\n' + clashnodes)
                        for onenode in clashnodes.split('\n'):
                            try:
                                allonenode += '\n' + SubConvert.surge_to_all_url(onenode)
                            except Exception as ex:
                                LocalFile.write_LogFile('Main-Line-211-Exception:' + str(ex) + '\nonenode:\n' + onenode)
                    elif (onode['type'] == 'sssub'):
                        if(clashnodes.find('[{"remarks":') > -1 and clashnodes.find('"server_port":"') == -1):
                            clashnodes = clashnodes.replace('"plugin_opts":null', '"plugin_opts":"null"')
                            for onenode in range(len(clashnodes)):
                                try:
                                    wnode = json.loads(clashnodes[onenode])
                                    allonenode += '\nss://' + base64.b64encode((wnode['method'] + ':' + wnode['password'] + '@' + wnode['server'] + ':' + wnode['server_port']).encode('utf-8')).decode('utf-8') + '#' + wnode['remarks']
                                except Exception as ex:
                                    LocalFile.write_LogFile('Main-Line-197-Exception:' + str(ex) + '\nonenode:\n' + onenode)
                    # 添加单个列表进所有列表
                    for onenode in allonenode.split('\n'):
                        try:
                            # 生成前半部节点，用于去重
                            if(onenode.find('#') > -1):
                                xnode = onenode.split('#', 1)[0]
                            else:
                                xnode = onenode
                            if(len(onenode) > 10240):
                                LocalFile.write_LogFile('Line-220-main-clashnodes:' + str(clashnodes) + '\nonenode:\n' + onenode)
                                onenode = ''
                            if (onenode.find('://') > -1 and onenode.find('trojan://@') == -1 and oldallonenode.find(xnode) == -1):
                                iii += 1
                                print('Main-Line-263-已添加(clash-node-url-id:' + str(ii)+ ')-onenode-id-' + str(iii) + '-onenode-url:\n' + onenode)
                                oldallonenode = onenode + '\n' + oldallonenode
                            else:
                                print('Main-Line-266-已过滤(clash-node-url-id:' + str(ii)+ ')-onenode-id-' + str(iii) + '-Find-Index-Allonenode:' + str(allonenode.find(onenode)) + '\n' + onenode)
                        except Exception as ex:
                            LocalFile.write_LogFile('Main-Line-268-Exception:' + str(ex) + '\nclashnodes:\n' + clashnodes + '\nonenode:\n' + onenode)
            except Exception as ex:
                LocalFile.write_LogFile('Main-Line-269-Exception:' + str(ex) + '\nonode_upurl:\n' + onode_upurl)
            nodeurl = nodeurl + '\n' + i
    # 将节点更新时间等写入配置文件
    if (nodeurl.find('uptime') > -1):
        LocalFile.write_LocalFile('./res/node.json', nodeurl.strip('\n'))
    print('Main-Line-275:node.json已更新，共更新网址[' + str(iii) + ']，Node-Txt-oldallonenode-size:' + str(len(oldallonenode)) + '')

    # 重新生成节点文件
    ii = 0
    iii = 0
    allsize = 0
    allnodes = base64.b64decode(LocalFile.read_LocalFile('./o/allnode.txt')).decode('utf-8')
    oldallonenode = allnodes + '\n' + oldallonenode
    nodes = ''
    allnodes = ''
    for onenode in oldallonenode.split('\n'):
        try:
            if(onenode.find('#') > -1):
                onenode = onenode.split('#', 1)[0]
            if (len(onenode) < 2048 and onenode.find('://') > -1 and allnodes.find(onenode) == -1):
                if(len(nodes) >= 3072000): # 3M
                    nodes = base64.b64encode(nodes.strip('\n').encode('utf-8')).decode('utf-8')
                    LocalFile.write_LocalFile('./res/nod-' + str(ii) + '.txt', nodes)
                    allsize += len(nodes)
                    ii += 1
                    nodes = ''
                iii += 1
                nodes = nodes + onenode + '\n'
            # allnodes只作过滤用，过滤完丢弃
            allnodes = allnodes + onenode + '\n'
        except Exception as ex:
            LocalFile.write_LogFile('Main-Line-364-Exception:' + str(ex) + '\nonenode:' + onenode)
    nodes = base64.b64encode(nodes.strip('\n').encode('utf-8')).decode('utf-8')
    LocalFile.write_LocalFile('./res/nod-' + str(ii) + '.txt', nodes)
    print('Main-Line-367-Node整理成功，共有记录' + str(iii) + '条记录，最后文本记录为：node-' + str(ii) + '.txt。')
    allsize += len(clashnodes)
    print('Main-Line-369-Node-Txt-allonenode-size:' + str(allsize) + '')

# 从vpei.txt节点列表中，筛选出部分节点，统一名称，生成转换成各种格式的订阅文件等
if(menu == 'optnode'):
    try:
        # 名称+端口整体过滤 处理临时数据和网络失效数据中vmess同一IP和端口过滤列表
        fakeip = LocalFile.read_LocalFile("./res/fakeip.txt")
        fakedomain = LocalFile.read_LocalFile("./res/fakedomain.txt")
        fakeinfo = fakeip + '\n' + fakedomain
        # 读取代理节点，优先使用最新生成的节点列表
        if(os.path.exists('./res/nod-0.txt')):
            allonenode = LocalFile.read_LocalFile('./res/nod-0.txt')
        else:
            allonenode = LocalFile.read_LocalFile('./res/nod-1.txt')
        allonenode = base64.b64decode(allonenode).decode('utf-8')
        print('Get-allonenode.txt: \n' + str(len(allonenode)))
        # 逐条对读取链接进行过滤和测试
        onenode = ''
        newallonenode = ''
        allnode = ''
        cnnode = ''
        errnode = ''
        newoldnode = ''
        oldname = ''
        newname = ''
        server = ''
        merged_nodelink_ping = []
        class Department:#自定义的元素
            def __init__(self, id, name, id2):
                self.id = id
                self.name = name
                self.id2 = id2 #备用字段
        datecont = time.strftime('%m-%d', time.localtime(time.time()))
        ii = 0
        iii = 0
        iiii = 0
        if(allonenode != ''):
            # 获取随机数值，按节点列表，取随机数整数，避免同一网站节点过多，提高节点列表生存时间
            rint = len(allonenode.split('\n'))
            rint = int(rint/404) + 1    # 则值不能为0
            rint = 1                    # 按顺序取所有值
            if(rint > 3):
                rint = random.randint(2, rint)
            for j in allonenode.split('\n'):
                try:
                    ii += 1
                    # 备用列表前10条记录必选，其他按照随机数rint间隔筛选
                    if((ii % rint == 0 or ii <= 20) and iii < 800):
                        print('\nLine-353-j-' + str(ii) + ':' + j)
                        oldname = ''
                        newname = ''
                        cipher = ''
                        server = ''
                        port = 0
                        password = ''
                        net = ''
                        # j = 'vmess://eyJwcyI6ICLwn4ev8J+HtS3ml6XmnKwtMTE3anAxLmJmeXVuLnRvcCIsICJhZGQiOiAiMTE3anAxLmJmeXVuLnRvcCIsICJwb3J0IjogIjEzNTY4IiwgInR5cGUiOiAidm1lc3MiLCAiaWQiOiAiODgyMTdmNTktZDk2ZS00NzhhLTgyYzktNDJjNDJjMjcyYmUwIiwgImFpZCI6ICIwIiwgIm5ldCI6ICJncnBjIiwgInBhdGgiOiAiLyIsICJob3N0IjogIjExN2pwMS5iZnl1bi50b3AiLCAidGxzIjogInRydWUiLCAic2N5IjogImF1dG8ifQ=='
                        if (j.find("vmess://") == 0):
                            onenode = SubConvert.check_url_v2ray_vmess(j)
                            onenode = base64.b64decode(onenode[8:].encode('utf-8')).decode('utf-8')
                            if(onenode != ''):
                                node = json.loads(onenode.encode('utf-8').decode('utf-8'))
                                # 可以忽略的代码
                                if(node['net'] == 'grpc' or node['net'] == 'h2'):
                                    node['tls'] = 'true'
                                #if(node['net'] == 'grpc' and node['tls'] == 'false'):
                                #    LocalFile.write_LogFile('Main-Line-372-Info-grpc-j:' + j + '\nnode:' + onenode)
                                oldname = node['ps']
                                cipher = node['scy']
                                server = node['add']
                                port = node['port']
                                password = node['id']
                                net = node['net']
                                if(server != '' ):
                                    newname = IpAddress.get_country(server) + '-' + server
                                    node['type'] = 'vmess'
                                    node['ps'] = newname #.decode('utf-8')
                                    onenode = json.dumps(node, ensure_ascii = False)
                                else:
                                    onenode = ''
                            if (cipher == 'aes-128-cfb' or cipher == 'aes-256-cfb' or cipher == 'aes-128-ctr' or cipher == 'rc4' or cipher == 'rc4-md5' or cipher == 'chacha20-ietf' or cipher == 'zero'):
                                ii = ii - 1
                                continue
                            # vmess标题需要固定,不动态添加时间
                            # newname = '[' + datecont + ']-' + IpAddress.get_country(node['add']) + '-'+ str(ii).zfill(3) + '-' + node['add']
                            # onenode = node.replace('"ps": "'+StrText.get_str_btw(node, '"ps": "', '"', 0), '"ps": "'+ newname, 1)
                            if (newname.find('.') > -1 and onenode != ''):
                                onenode = "vmess://" + base64.b64encode(onenode.encode('utf-8')).decode('utf-8')
                            else:
                                errnode = errnode + '\n' + j + '\n' + onenode
                                ii = ii - 1
                                onenode = ''
                                newname = ''
                        elif (j.find("ss://") == 0):
                            onenode = SubConvert.url_ss_to_json(j)
                            if(onenode != ''):
                                node = json.loads(onenode)
                                cipher = node['cipher']
                                password = node['password']
                                server = node['server']
                                port = node['port']
                                password = node['password']
                                oldname = node['name']
                                ip_country = IpAddress.get_country(server)
                                newname = '[' + datecont + ']-' + ip_country + '-'+ str(ii).zfill(3) + '-' + server
                                
                                # 端口不能为非数字，过滤V2ray不支持的加密方式的节点
                                if(cipher == 'chacha20-poly1305'):
                                    ii = ii - 1
                                    continue

                                # aes-256-gcm:n8w4StnbVD9dmXYn4Ajt87EA@212.102.54.163:31572#title
                                onenode = cipher + ':' + password + '@' + server + ':' + str(port)
                                onenode = base64.b64encode(onenode.encode("utf-8")).decode("utf-8")
                                onenode = 'ss://' + onenode + '#' + newname
                            else:
                                errnode = errnode + '\n' + j + '\n' + onenode
                                ii = ii - 1
                                onenode = ''
                                newname = ''
                        elif (j.find("trojan://") == 0):
                            #trojan://28d98f761aca9d636f44db62544628eb@45.66.134.219:443#5.66.134.219
                            #trojan://28d98f761aca9d636f44db62544628eb@45.66.134.219:443?sni=123#45.66.134.219
                            if (j.find("#") == -1):
                                j = j + "#0"
                            onenode = j
                            node = onenode.split("#", 1)
                            password = StrText.get_str_btw(j, "trojan://", "@", 0).replace('<', '').replace('>', '')
                            server = StrText.get_str_btw(j, "@", ":", 0)
                            ip_country = IpAddress.get_country(server)
                            port = node[0].rsplit(':', 1)[1]
                            oldname = node[1]
                            newname = '[' + datecont + ']-' + ip_country + '-'+ str(ii).zfill(3) + '-' + server
                            if(port.isnumeric() and password != '' and password != 'null'):
                                onenode = node[0] + "#" + newname
                            else:
                                errnode = errnode + '\n' + j + '\n' + onenode
                                ii = ii - 1
                                onenode = ''
                                newname = ''
                        elif (j.find("vless://") == 0):
                            #vless://892ebb75-7055-3007-8d16-356e65c6a49a@45.66.134.219:443?encryption=none&security=tls&sni=45.66.134.219&type=ws&host=45.66.134.219&path=%2fv1t-vless#filename
                            if (j.find('#') == -1):
                                j = j + '#0'
                            onenode = j
                            password = StrText.get_str_btw(onenode, 'vless://', '@', 0)
                            node = onenode.split('#', 1)
                            port = node[0].rsplit(':', 1)[1]
                            oldname = node[1]
                            server = StrText.get_str_btw(onenode, '@', ':', 0)
                            ip_country = IpAddress.get_country(server)
                            newname = '[' + datecont + ']-' + ip_country + '-'+ str(ii).zfill(3) + '-' + server
                            onenode = node[0] + '#' + newname
                        elif (j.find("ssr://") == 0):
                            #ssr://ip:port:protocol:method:blending:password/?remarks=other text
                            #159.65.1.189:5252:auth_sha1_v4:aes-256-cfb:http_simple:NTJzc3IubmV0/?obfsparam=&protoparam=&group=d3d3LnNzcnNoYXJlLmNvbQ&remarks=RE1fTm9kZQ
                            onenode = StrText.get_str_base64(j[6:])
                            # onenode = base64.b64decode(onenode).decode('utf-8', errors='ignore')
                            onenode = base64.b64decode(onenode).decode('utf-8')
                            oldname = StrText.get_str_btw(onenode + '&','remarks=', '&', 0)
                            server = onenode.split(':')[0]
                            port = onenode.split(':')[1]
                            protocol = onenode.split(':')[2]
                            if (protocol == 'auth_chain_a' or protocol == 'zero'):
                                ii = ii - 1
                                continue

                            ip_country = IpAddress.get_country(server)
                            newname = base64.b64encode((ip_country + '-'+ server).encode('utf-8')).decode('utf-8')
                            onenode = onenode.replace(oldname, newname)
                            onenode = "ssr://" + base64.b64encode(onenode.encode('utf-8')).decode('utf-8')
                            #onenode = ''
                            #ii = ii - 1
                        else:
                            ii = ii - 1
                            continue
                        
                        # port1 = str(isinstance(port, int))
                        # port2 = str(isinstance(port, str))
                        port = str(port)
                        # port3 = port.isdigit()
                        # 端口不能为非数字，过滤V2ray不支持的加密方式的节点
                        if(onenode == '' or port.isdigit() == False):
                            errnode = errnode + '\n' + j + '\n' + onenode
                            ii = ii - 1
                            continue
                        # ondenode需为非空
                        if (IsValid.isIPorDomain(server) and (onenode.find("vmess://") == 0 or onenode.find("ss://") == 0 or onenode.find("ssr://") == 0 or onenode.find("trojan://") == 0 or onenode.find("vless://") == 0)):
                            stime = 0
                            stime = 99 # PingIP.tcp_ping(server, port)
                            print('stime:' + str(stime))

                            # ss，trjon等数据，过滤节点名，再过滤
                            server = server + ':' + port + ':' + password
                            #if(stime <= 0 or fakeinfo.find(server + ':' + port) > -1):
                            if(fakeinfo.find(server) > -1):
                                stime = 9999
                                errnode = errnode + '\n' + j + '\n' + onenode
                                print('Main-Line-525-处理错误链接(iii:' + str(iii) + '-ii-' + str(ii) + ')-onenode:\n' + onenode)
                            else:
                                # 转换软件不支持，暂时过滤
                                if(net == 'grpc' or net == 'h2'):
                                    ii = ii - 1
                                    continue
                                # 取所有生成国内国外节点的原始数据
                                allnode = allnode + '\n' + j
                                print('Rename node ' + oldname.strip('\n') + ' to ' + newname)
                                if(newname.find(u'中国') > -1 or newname.find(u'省') > -1 or newname.find(u'上海') > -1 or newname.find(u'北京') > -1 or newname.find(u'重庆') > -1 or newname.find(u'内蒙') > -1):
                                    if(iiii < 100):
                                        cnnode = cnnode + '\n' + onenode
                                        iiii += 1
                                    else:
                                        newallonenode = newallonenode + '\n' + j
                                else:
                                    iii += 1
                                    merged_nodelink_ping.append(Department(stime, onenode, '1'))
                                    print('Main-Line-468-已添加(iii:' + str(iii) + '-ii-' + str(ii)+ ')-onenode:\n' + onenode)
                    else:                    
                        newallonenode = newallonenode + '\n' + j
                except Exception as ex:
                    LocalFile.write_LogFile('Main-Line-547-Exception:' + str(ex) + '\nConT:' + j)
            # 生成ErrNode错误列表
            LocalFile.write_LocalFile('./res/errnode.txt', errnode)

            # 生成国内节点
            cnnode = base64.b64encode(cnnode.strip('\n').encode('utf-8')).decode('utf-8')
            LocalFile.write_LocalFile('./o/nodecn.txt', cnnode)

            # 生成国内国外所有节点
            allnode = base64.b64encode(allnode.strip('\n').encode('utf-8')).decode('utf-8')
            LocalFile.write_LocalFile('./o/allnode.txt', allnode)
        
            # 生成挑选后剩余节点，存入node-0.txt        
            newallonenode = base64.b64encode(newallonenode.strip('\n').encode('utf-8')).decode('utf-8')
            LocalFile.write_LocalFile('./res/nod-0.txt', newallonenode)
        else:
            print('Main-Line-421-allonenode-空')

        # operator.attrgetter('id','name')#参数为排序依据的属性，可以有多个，这里优先id，使用时按需求改换参数即可
        merged_nodelink_ping.sort(key = operator.attrgetter('id', 'name'))#使用时改变列表名即可 
        # 此时Departs已经变成排好序的状态了，排序按照id优先，其次是name，遍历输出查看结果

        # 合并整理完成的国外混合节点
        allnode = ''
        if(len(merged_nodelink_ping) > 0):
            try:
                for depart in merged_nodelink_ping:
                    onenode = depart.name
                    print('onenodeurl-' + str(depart.id) + ':\n' + onenode)
                    if (allnode.find(onenode) == -1):
                        allnode = allnode + onenode + '\n'
                allnode = base64.b64encode(allnode.encode('utf-8')).decode('utf-8')
                LocalFile.write_LocalFile('./res/node.txt', allnode)
                print('国外混合节点已生成，下一步将生成Clash节点。')
            except Exception as ex:
                LocalFile.write_LogFile('Main-Line-483-Exception:' + str(ex) + '\nlen(merged_nodelink_ping):' + len(merged_nodelink_ping))
        else:
            print('Main-Line-416-merged_nodelink_ping:\n' + str(merged_nodelink_ping))
    except Exception as ex:
        LocalFile.write_LogFile('Main-Line-533-Exception:' + str(ex))

# 从node.txt节点列表中，转换成各种Clash格式的配置文件
if(menu == 'allclash'):
    # 读取代理节点，优先使用最新生成的节点列表
    if(os.path.exists('./o/allnode.txt')):
        allnodetxt = LocalFile.read_LocalFile('./o/allnode.txt')
    else:
        allnodetxt = LocalFile.read_LocalFile('./res/node.txt')
    allnodetxt = base64.b64decode(allnodetxt).decode('utf-8')
    # 逐条读取链接，并生成CLASH国外订阅链接 
    clashurl = ''
    openclashurl = ''
    clash_node_url = ''
    proxies_url = ''
    clashname = ''
    telename = ''
    nodecount = 256
    datecont = time.strftime('%m-%d', time.localtime(time.time()))
    if(len(allnodetxt) > 0):
        for j in allnodetxt.split('\n'):
            try:
                # 完成添加节点数后，其他节点链接则忽略
                if (nodecount > 0):
                    onenode = ''
                    cipher = ''
                    # j = 'ssr://dHctMi5naXRvLmNjOjMzNDA1OmF1dGhfYWVzMTI4X21kNTphZXMtMjU2LWNmYjp0bHMxLjJfdGlja2V0X2F1dGg6T1dsbVlYTjAvP2dyb3VwPVUxTlNVSEp2ZG1sa1pYSSZyZW1hcmtzPTVyS3o1WTJYNTV5QjZhbTc2YW1zNWJxWDViaUNMWFIzTFRJdVoybDBieTVqWXc9PSZvYmZzcGFyYW09NzctOWEtLV92ZS1fdlRjMTc3LTk3Ny05TU8tX3ZXcnZ2NzEzYm14dlotLV92WGRwYm1ydnY3MTNlZS1fdlhMdnY3MTI3Ny05NzctOWIyMCZwcm90b3BhcmFtPTc3LTkyN252djczdnY3MTY3Ny05R3UtX3ZlLV92ZS1fdlE='
                    # j = 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpHIXlCd1BXSDNWYW9AMTYyLjI1MS42MS4yMjE6ODA0'    
                    print('Main-Line-654-j-' + str(nodecount) + '-j-' + j)
                    if (j.find("vmess://") == 0):
                        j = SubConvert.check_url_v2ray_vmess(j)
                        j = base64.b64decode(j[8:].encode('utf-8')).decode('utf-8')
                        node = json.loads(j)
                        # oldname = node['ps']
                        newname = node['ps']
                        cipher = node['scy']
                        onenode = SubConvert.v2ray_vmess_to_clash(j)
                    elif (j.find("ss://") == 0):             
                        onenode = SubConvert.url_ss_to_json(j)
                        if(onenode != ''):
                            node = json.loads(onenode)
                            cipher = node['cipher']
                            if(cipher == 'ss'):
                                errnode = errnode + '\n' + j + '\n' + onenode
                                onenode = ''
                                newname = ''
                            password = node['password'].replace('<', '').replace('>', '').replace('!', '')
                            server = node['server']
                            port = node['port']
                            oldname = node['name']
                            newname = '[' + datecont + ']-' + IpAddress.get_country(server) + '-'+ str(nodecount).zfill(3) + '-' + server
                            # 格式一
                            # onenode = '- cipher: ' + cipher + '\n  name: \'' + newname + '\'\n  password: ' + password + '\n  server: ' + server + '\n  port: ' + str(port) + '\n  type: ss'
                            # 格式二
                            onenode = '  - {name: \'' + newname + '\', cipher: ' + cipher + ', password: ' + password + ', server: ' + server + ', port: ' + str(port) + ', type: ss}'
                        else:
                            errnode = errnode + '\n' + j + '\n' + onenode
                            onenode = ''
                            newname = ''
                    elif (j.find("trojan://") == 0):
                        # trojan://28d98f761aca9d636f44db62544628eb@45.66.134.219:443#%f0-45.66.134.219
                        # trojan://ee4fff2a-540e-4ac7-a16a-935567dfc36b@guoxiangdang.com:995?flow=xtls-rprx-origin&security=tls&sni=SNI&alpn=h2%2Chttp%2F1.1&type=tcp&headerType=none&host=host.com#aiguoxiangdang.com
                        if(j.find('#') == -1):
                            j = j + '#'
                        oldname = j.split("#", 1)[1]
                        password = StrText.get_str_btw(j, "trojan://", "@", 0).replace('<', '').replace('>', '')
                        server = StrText.get_str_btw(j, "@", ":", 0)
                        cipher = 'none' # trojan无cipher
                        if(server.find('@') > -1):
                            server = server.split('@')[1]
                        newname = '[' + datecont + ']-' + IpAddress.get_country(server) + '-'+ str(nodecount).zfill(3) + '-' + server
                        if (j.find("?") > -1):
                            port = StrText.get_str_btw(StrText.get_str_btw(j, "@", "#", 0), ":", "?", 0)
                        else:
                            port = StrText.get_str_btw(j, "@", "#", 0).split(":", 1)[1]
                        if(port.isnumeric() and password != '' and password != 'null'):
                            # 格式一
                            onenode = '- name: \'' + newname + '\'\n  type: trojan\n  server: ' + server + '\n  port: ' + str(port) + '\n  password: ' + password
                            if(j.find('?') > -1):
                                tmpstr = StrText.get_str_btw(j, "?", "#", 0) + '&'
                                if (j.find("sni=") > -1):
                                    onenode = onenode + '\n  sni: ' + StrText.get_str_btw(tmpstr, "sni=", "&", 0)
                                onenode = onenode + '\n  tls: true'
                                onenode = onenode + '\n  allowInsecure: true'
                                if (j.find("type=") > -1):
                                    onenode = onenode + '\n  netword: ' + StrText.get_str_btw(tmpstr, "type=", "&", 0)
                                if (j.find("host=") > -1):
                                    onenode = onenode + '\n  host: ' + StrText.get_str_btw(tmpstr, "host=", "&", 0)
                                if (j.find("path=") > -1):
                                    onenode = onenode + '\n  path: ' + StrText.get_str_btw(tmpstr, "path=", "&", 0)
                                if (j.find("encryption=") > -1):
                                    onenode = onenode + '\n  encryption: ' + StrText.get_str_btw(tmpstr, "encryption=", "&", 0)
                                if (j.find("plugin=") > -1):
                                    onenode = onenode + '\n  plugin: ' + StrText.get_str_btw(tmpstr, "plugin=", "&", 0)
                                if (j.find("headerType=") > -1):
                                    onenode = onenode + '\n  headerType: ' + StrText.get_str_btw(tmpstr, "headerType=", "&", 0)
                                if (j.find("peer=") > -1):
                                    onenode = onenode + '\n  peer: ' + StrText.get_str_btw(tmpstr, "peer=", "&", 0)
                                if (j.find("tfo=") > -1):
                                    onenode = onenode + '\n  tfo: ' + StrText.get_str_btw(tmpstr, "tfo=", "&", 0)
                                if (j.find("alpn=") > -1):
                                    alpn = StrText.get_str_btw(tmpstr, "tfo=", "&", 0).replace('%2C',',').replace('%2F','/') + ','
                                    onenode = onenode + '\n  alpn: '
                                    for ia in alpn.split(','):
                                        if(ia != ''):
                                            onenode = onenode + ia + ','
                                onenode = onenode + '\n  skip-cert-verify: true'
                                onenode = onenode.strip(',')
                            
                            # 格式二
                            # trojan://Ty33ylFA4u6A5e0NE3wRFp3DIa8lZOzC87CeKnxYgpSOSa2ZaXBjDDSY9qCcxR@45.64.22.55:443?security=tls&sni=flowery.meijireform.com&type=tcp&headerType=none
                            onenode = 'name: \'' + newname + '\', server: ' + server + ', port: ' + str(port) + ', type: trojan, password: ' + password
                            if(j.find('?') > -1):
                                tmpstr = StrText.get_str_btw(j, "?", "#", 0) + '&'
                                #if (j.find("allowInsecure=") > -1):
                                #    if(StrText.get_str_btw(tmpstr, "allowInsecure=", "&", 0) == '1'):
                                #        onenode = onenode + ', skip-cert-verify: true'
                                #    else:
                                #        onenode = onenode + ', skip-cert-verify: false'

                                #"network": "tcp",
                                #"security": "tls",
                                #"tlsSettings": {
                                #"allowInsecure": true,
                                #"serverName": "flowery.meijireform.com"
                                #}
                                #, network: tcp, true: tls, allowInsecure: true, sni: flowery.meijireform.com
                                if (j.find("sni=") > -1):
                                    onenode = onenode + ', sni: ' + StrText.get_str_btw(tmpstr, "sni=", "&", 0)
                                if (j.find("flow=") > -1):
                                    onenode = onenode + ', flow: ' + StrText.get_str_btw(tmpstr, "flow=", "&", 0)
                                onenode = onenode + ', tls: true'# + StrText.get_str_btw(tmpstr, "security=", "&", 0).replace('tls', 'true')
                                if (j.find("type=") > -1):
                                    onenode = onenode + ', netword: ' + StrText.get_str_btw(tmpstr, "type=", "&", 0)
                                if (j.find("host=") > -1):
                                    onenode = onenode + ', host: ' + StrText.get_str_btw(tmpstr, "host=", "&", 0)
                                if (j.find("path=") > -1):
                                    onenode = onenode + ', path: ' + StrText.get_str_btw(tmpstr, "path=", "&", 0)
                                if (j.find("encryption=") > -1):
                                    onenode = onenode + ', encryption: ' + StrText.get_str_btw(tmpstr, "encryption=", "&", 0)
                                if (j.find("plugin=") > -1):
                                    onenode = onenode + ', plugin: ' + StrText.get_str_btw(tmpstr, "plugin=", "&", 0)
                                if (j.find("headerType=") > -1):
                                    onenode = onenode + ', headerType: ' + StrText.get_str_btw(tmpstr, "headerType=", "&", 0)
                                if (j.find("peer=") > -1):
                                    onenode = onenode + ', peer: ' + StrText.get_str_btw(tmpstr, "peer=", "&", 0)
                                if (j.find("tfo=") > -1):
                                    onenode = onenode + ', tfo: ' + StrText.get_str_btw(tmpstr, "tfo=", "&", 0)
                                if (j.find("alpn=") > -1):
                                    alpn = StrText.get_str_btw(tmpstr, "tfo=", "&", 0).replace('%2C',',').replace('%2F','/') + ','
                                    onenode = onenode + ', alpn: ' + alpn
                            if(onenode.find('skip-cert-verify:') == -1):
                                onenode = onenode + ', skip-cert-verify: false'
                            else:
                                onenode = onenode + ', skip-cert-verify: ' + StrText.get_str_btw(tmpstr, "skip-cert-verify=", "&", 0)
                            if(onenode.find('udp:') == -1):
                                onenode = onenode + ', udp: true'
                            onenode = '  - {' + onenode + '}'
                    elif (j.find("ssr://") == 0):
                        #ssr://ip:port:protocol:method:blending:password/?obfsparam=&protoparam=&group=&remarks=remarks
                        #159.65.1.189:5252:auth_sha1_v4:rc4-md5:http_simple:NTJzc3IubmV0/?obfsparam=&protoparam=&group=d3d3LnNzcnNoYXJlLmNvbQ&remarks=remarks
                        #159.65.1.189:33099:origin:rc4-md5:http_simple:SGRzcndF/?obfsparam=ZG93bmxvYWQud2luZG93c3VwZGF0ZS5jb20&protoparam=&remarks=6Ziy5aSx5pWIZ2l0aHViLmNvbS9MZW9uNDA2IOS4reWbvS3pppnmuK8gSUVQTCBFcXVpbml4IEhLOCBDIDAxIDFHYnBzIE5ldGZsaXggSEJPIFRWQg&group=
                        # j = 'ssr://c2h6enpoay5ldWNkdXJsLm1lOjU2MTphdXRoX2FlczEyOF9tZDU6Y2hhY2hhMjAtaWV0ZjpwbGFpbjpiV0pzWVc1ck1YQnZjblEvP3JlbWFya3M9OEorSHB2Q2ZoN1l0NUxpSzVyVzM1YmlDTFhOb2VucDZhR3N1WlhWalpIVnliQzV0WlE9PSZwcm90b3BhcmFtPU5ERTNOVFU2Y1RFek5ETXpPREF4TXpJMiZvYmZzcGFyYW09Jmdyb3VwPWFIUjBjSE02THk5Mk1uSmhlWE5sTG1OdmJR'
                        onenode = StrText.get_str_base64(j[6:])
                        onenode = base64.b64decode(onenode).decode('utf-8')
                        node = onenode.split('/?')[0].split(':')
                        server = node[0]
                        port = node[1]
                        protocol = node[2]
                        cipher = node[3]
                        http_simple = node[4]
                        password = StrText.get_str_base64(node[5])
                        password = base64.b64decode(password).decode('utf-8').replace('<', '').replace('>', '')
                        remarks = ''
                        newname = '[' + datecont + ']-' + IpAddress.get_country(server) + '-'+ str(nodecount).zfill(3) + '-' + server
                        if(onenode.find('remarks=') > -1):
                            remarks = StrText.get_str_base64(StrText.get_str_btw((onenode + '&'), 'remarks=', '&', 0))
                            #remarks = base64.b64decode(remarks).decode('utf-8')
                        protoparam = ''
                        if(onenode.find('protoparam=') > -1):
                            protoparam = StrText.get_str_base64(StrText.get_str_btw((onenode + '&'), 'protoparam=', '&', 0))
                            #protoparam = base64.b64decode(protoparam).decode('utf-8')
                        obfsparam = ''
                        if(onenode.find('obfsparam=') > -1):
                            obfsparam = StrText.get_str_base64(StrText.get_str_btw((onenode + '&'), 'obfsparam=', '&', 0))
                            #obfsparam = base64.b64decode(obfsparam).decode('utf-8')
                        group = ''
                        if(onenode.find('group=') > -1):
                            group = StrText.get_str_base64(StrText.get_str_btw((onenode + '&'), 'group=', '&', 0))
                            group = base64.b64decode(group).decode('utf-8')
                            if(group == 'null'):
                                group = ''
 
                        # 格式一
                        # onenode = '- name: \'' + remarks + '\'\n  server: ' + server + '\n  port: ' + str(port) + '\n  protocol: ' + protocol + '\n  cipher: ' + cipher + '\n  obfs: ' + http_simple + '\n  obfs-param: ' + obfsparam + '\n  password: ' + password + '\n  protocol-param: ' + protoparam + '\n  group: ' + group + '\n  type: ssr'
                        # 格式二
                        #- {name: "linkthink.app", server: dg-hk-node02.linkthink.app, port: 12025, type: ssr, cipher: dummy, password: e5opjuLDEQ, protocol: origin, obfs: http_post, protocol-param: "", obfs-param: ajax.microsoft.com, udp: true}
                        # onenode = '  - {name: \'' + newname + '\', server: ' + server + ', port: ' + str(port) + ', type: ssr, cipher: ' + cipher + ', password: ' + password + ', protocol: ' + protocol + ', obfs: ' + http_simple + ', obfs-param: ' + obfsparam + ', protocol-param: ' + protoparam + ', group: ' + group + '}'
                        onenode = '  - {name: \'' + newname + '\', server: ' + server + ', port: ' + str(port) + ', type: ssr, cipher: ' + cipher + ', password: ' + password + ', protocol: ' + protocol + ', obfs: ' + http_simple + '}'
                    else:
                        print('Main-Line-723-已跳过-onenode:\n' + j)
                        continue

                    # 过滤无效和重复节点
                    if (onenode != '' and newname != '' and clashurl.find(onenode) == -1 and clashname.find(newname) == -1):
                        # Clash的cipher不支持则忽略
                        allcipher = 'chacha20-ietf xchacha20'
                        allcipher = allcipher.upper()
                        if (allcipher.find(cipher.upper()) > -1):
                            LocalFile.write_LogFile('Main-Line-799-allcipher.find(cipher.upper())-j:' + j + '\ncipher:' + cipher)
                            continue
                        if(newname.find(u'省') > -1 or newname.find(u'上海') > -1 or newname.find(u'北京') > -1 or newname.find(u'重庆') > -1 or newname.find(u'内蒙') > -1):
                            continue
                        nodecount = nodecount - 1
                        clashname = clashname + '  - \'' + newname + '\'\n'
                        clashurl = clashurl + onenode + '\n'
                        # openclashurl = openclashurl + onenode + '\n  udp: true\n'
                        # openclashurl = openclashurl + onenode[:-1] + ', udp: true}\n'
                        openclashurl = openclashurl + onenode + '\n'
                        clash_node_url = clash_node_url + '\n' + onenode.replace('  - {', '  - {"').replace('"', '').replace('\'', '').replace(': ', '": "').replace(', ', '", "').replace('}', '"}')
                        if(newname.find('伊朗') == -1 and newname.find(u'中非') == -1):
                            telename = telename + '  - \'' + newname + '\'\n'
                            proxies_url = proxies_url + onenode + '\n'
                        print('Main-Line-740-已添加-onenode:\n' + onenode)
                    else:
                        print('Main-Line-742-已过滤-newname:' + newname + '-clashurl.find(onenode):' + str(clashurl.find(onenode)) + '-clashname.find(newname):' + str(clashname.find(newname)) + '\nonenode:' + onenode + '\n')
                else:
                    print('\n[保留' + str(nodecount) + '条节点，忽略多余节点]:' + j)
            except Exception as ex:
                LocalFile.write_LogFile('Main-Line-669-j:' + j + '\nException:' + str(ex))
        clashname = clashname.rstrip('\n')
        telename = telename.rstrip('\n')

        clashurl = clashurl.rstrip('\n')
        openclashurl = openclashurl.rstrip('\n')
        clash_node_url = clash_node_url.rstrip('\n')
        proxies_url = proxies_url.rstrip('\n')

        print('clashname:\n' + clashname)
        print('clashurl:\n' + clashurl)

        # 合并替换Clash节点信息，下载后回车行丢失
        # clash_1 = NetFile.down_res_file(resurl, 'clash-1.txt', 240, 120)
        # clash_2 = NetFile.down_res_file(resurl, 'clash-2.txt', 240, 120)
        if(clashname != ''):
            with open("./res/clash-1.txt", "r", encoding='utf-8') as f:  # 打开文件
                clash_1 = f.read()  # 读取文件
            with open("./res/clash-2.txt", "r", encoding='utf-8') as f:  # 打开文件
                clash_2 = f.read()  # 读取文件

            # 写入节点文件到本地ClashNode文件
            LocalFile.write_LocalFile('./o/proxies.txt', 'proxies:\n' + proxies_url)
            print('ClashNode-Proxies文件成功写入。(纯节点)')

            tmp = clash_1.replace("clash-url.txt", clashurl)
            tmp = tmp.replace("clash-name.txt", clashname)
            tmp = tmp.replace("tele-name.txt", telename)
            tmp = tmp.replace("clash-2.txt", clash_2)
            tmp = tmp.replace('\nexternal-ui: \'/usr/share/openclash/dashboard\'', '')
            # 写入节点文件到本地Clash文件
            LocalFile.write_LocalFile('./o/clash.yaml', tmp)
            print('Clash文件成功写入。')

            tmp = clash_1.replace("clash-url.txt", openclashurl)
            tmp = tmp.replace("clash-name.txt", clashname)
            tmp = tmp.replace("tele-name.txt", telename)
            tmp = tmp.replace("clash-2.txt", clash_2)
            # 写入节点文件到本地OpenClash文件
            LocalFile.write_LocalFile('./o/openclash.yaml', tmp)
            print('OpenClash文件成功写入。(添加UDP为True的参数)')

            tmp = 'proxies:' + clash_node_url
            # 写入节点文件到本地ClashNode文件
            LocalFile.write_LocalFile('./o/clashnode.txt', tmp)
            print('ClashNode文件成功写入。(纯节点)')
    else:
        print('Main-Line-625:数据获取失败，暂停生成CLASH等链接。\nallnodetxt:' + allnodetxt)