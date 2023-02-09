# -*- coding: UTF-8 -*-
from configparser import ConfigParser
import os, shutil, sys
import re
import datetime
import tarfile
import qiniu
from tqdm import tqdm
import traceback

# session用于和 nessus scanner 之间的通信
import requests
import xml.etree.ElementTree as ET
session = requests.session()
# 去除nessus自签名证书的警告
requests.packages.urllib3.disable_warnings()


def read_conf(conf_path: str) -> dict:
    ''' 读取配置文件

    Args:
        conf_path(str): 配置文件路径

    Return:
        {
            'nessus': {'username': 'xxx', 'password': 'xxx', 'host': 'xxx', 'plugin_set': 'xxx'}, 
            'v2ray': {'json': ''},
            'oss': {'url': '', 'size': '', 'etag': '', 'plugin_set': ''},
        }
    '''
    import json
    ret = {
        'nessus': {'username': '', 'password': '', 'host': '', 'plugin_set': ''},
        'v2ray': {'json': ''},
        'oss': {'url': '', 'size': '', 'etag': '', 'plugin_set': ''},
    }  

    # 配置文件必须存在且内容必须合法
    print('[Info] 读取配置...')
    try:
        if not os.path.exists(conf_path):
            print(' -> [Warning] nessus-update.conf不存在，写入默认配置')
            with open(conf_path, 'w') as f:
                f.write('[nessus]\n')
                f.write('username    =   xxx\n')
                f.write('password    =   xxx\n')
                f.write('host        =   localhost:8834\n')
                f.write('\n')
                f.write('[v2ray]\n')
                f.write('address     =   nessus-update.chenql.cn\n')
                f.write('port        =   8835\n')
                f.write('user        =   xxx\n')
                f.write('\n')
                f.write('[oss]\n')
                f.write('url         =   http://static.chenql.cn/nessus/all-2.0.tar.gz\n')
                f.write('\n')
        config = ConfigParser()
        config.read(conf_path, encoding='UTF-8')
        ret['nessus']['username'] = config.get('nessus', 'username', fallback='username')
        ret['nessus']['password'] = config.get('nessus', 'password', fallback='password')
        ret['nessus']['host'] = 'https://' + re.sub('http://|https://', '', config.get('nessus', 'host', fallback='localhost:8834'))
        v2ray_json = {
            'log': {'loglevel': 'warning'},
            'reverse': {
                'bridges': [
                    {'tag': 'bridge', 'domain': '{}.nessus-tunnel'.format(config.get('v2ray', 'user', fallback='placeholder'))}
                ]
            },
            'outbounds': [
                {
                    'tag': 'toProxy',
                    'protocol': 'vmess',
                    'settings': {
                        'vnext': [{
                            'address': config.get('v2ray', 'address', fallback='nessus-update.chenql.cn'),
                            'port': config.getint('v2ray', 'port', fallback=0),
                            'users': [{'id': '1b73a61f-29b3-4633-a804-53c371e48e75', 'security': 'auto'}]
                        }]
                    }
                },
                {'tag': 'direct', 'protocol': 'freedom'}
            ],
            'routing': {
                'rules': [
                    {
                        'type': 'field',
                        'inboundTag': ['bridge'],
                        'domain': ['full:{}.nessus-tunnel'.format(config.get('v2ray', 'user', fallback='placeholder'))],
                        'outboundTag': 'toProxy'
                    },
                    {
                        'type': 'field',
                        'inboundTag': ['bridge'],
                        'outboundTag': 'direct'
                    }
                ]
            }
        } 
        ret['v2ray']['json'] = json.dumps(v2ray_json)
        ret['oss']['url'] = config.get('oss', 'url', fallback='http://static.chenql.cn/nessus/all-2.0.tar.gz')
    except:
        print(' -> [Error] 读取配置文件失败')
        traceback.print_exc(limit=1)

    return ret


def test_conf(config:dict) -> bool:
    ''' 测试配置是否有效

    Args:
        conf_path(str): 配置文件路径

    Return:
        True/False
    '''

    # nessus服务端必须有效
    print('[Info] 检查nessus配置...')
    try:
        # 无法连接或登录失败时终止验证
        r = session.post(
            '{}/login'.format(config['nessus']['host']), 
            verify=False, 
            headers={
                'X-Securitycenter': 'a04629e1-df01-5d5c-917f-f7f88beaa993',
                'User-Agent': 'SecurityCenter/5.5.2 (201709293113)'
            },
            data={'login': config['nessus']['username'], 'password': config['nessus']['password'], 'seq': 1}
        )
        assert r.status_code == 200, 'login failed'

        # 从Scanner中读取当前插件版本
        login_xml = ET.fromstring(r.content)
        token = login_xml.find('./contents/token').text
        # 未注册的新scanner的plugin_set标签值为空(None)
        config['nessus']['plugin_set'] = login_xml.find('./contents/plugin_set').text
        if not config['nessus']['plugin_set']:
            config['nessus']['plugin_set'] = ''
            print(' -> 登录成功，当前特征库版本 (plugin_set) = <null> (unregistered scanner)')
        else:
            print(' -> 登录成功，当前特征库版本 = {}'.format(config['nessus']['plugin_set']))
        r = session.post(
            '{}/logout'.format(config['nessus']['host']), 
            verify=False, 
            headers={
                'X-Cookie': 'token=' + token,
                'User-Agent': 'SecurityCenter/5.5.2 (201709293113)'
            },
            files={'seq': (None, 2), 'token': (None, token)}
        )
    except:
        print(' -> [Error] Nessus Scanner 登录失败')
        traceback.print_exc(limit=1)
        return False

    print('[Info] 检查OSS配置...')
    try:
        print(' -> 文件路径: {}'.format(config['oss']['url']))
        r = requests.head(config['oss']['url'])
        config['oss']['size'] = r.headers['Content-Length']
        config['oss']['etag'] = r.headers['Etag'][1:-1]
        config['oss']['plugin_set'] = r.headers['X-Qn-Meta-Plugin-Set']
        print(' -> 连接成功，特征库版本 (plugin_set) = {}'.format(config['oss']['plugin_set']))
    except:
        config['oss']['plugin_set'] = ''
        print(' -> [Warning] OSS连接失败/非法的URL')
        traceback.print_exc(limit=1)

    return True


def upload(local_file_info, scanner_info):
    ''' 使用本地完整包更新Scanner

    Args:
        local_file_info(dict): 本地完整包信息
        scanner_info(dict): Scanner配置信息
    '''

    print('[Info] 使用本地文件更新Scanner...')
    print(' -> path: {}'.format(local_file_info['path']))
    print(' -> plugin_set: {}'.format(local_file_info['plugin_set']))
    print(' -> seq_1(login)')
    r = session.post(
        '{}/login'.format(scanner_info['host']), 
        verify=False, 
        headers={
            'X-Securitycenter': 'a04629e1-df01-5d5c-917f-f7f88beaa993',
            'User-Agent': 'SecurityCenter/5.5.2 (201709293113)'
        },
        data={'login': scanner_info['username'], 'password': scanner_info['password'], 'seq': 1}
    )
    login_xml = ET.fromstring(r.content)
    token = login_xml.find('./contents/token').text

    print(' -> seq_2(upload)')
    with open(local_file_info['path'],'rb') as f:
        r = session.post(
            '{}/file/upload'.format(scanner_info['host']), 
            verify=False, 
            headers={
                'X-Cookie': 'token=' + token,
                'User-Agent': 'SecurityCenter/5.5.2 (201709293113)'
            },
            files={'token': (None, token), 'seq': (None, 2), 'Filedata': (os.path.basename(local_file_info['path']), f)}
        )

    print(' -> seq_3(process)')
    r = session.post(
        '{}/plugins/process'.format(scanner_info['host']), 
        verify=False, 
        headers={
            'X-Cookie': 'token=' + token,
            'User-Agent': 'SecurityCenter/5.5.2 (201709293113)'
        },
        files={'token': (None, token), 'seq': (None, 3), 'filename': (None, os.path.basename(local_file_info['path']))}
    )

    print(' -> seq_4(logout)')
    r = session.post(
        '{}/logout'.format(scanner_info['host']), 
        verify=False, 
        headers={
            'X-Cookie': 'token=' + token,
            'User-Agent': 'SecurityCenter/5.5.2 (201709293113)'
        },
        files={'seq': (None, 4), 'token': (None, token)}
    )
    print('[Info] 上传成功，请等待nessusd更新后自动重启')


def start_v2ray(config: str):
    import subprocess
    subprocess.run(
        [os.path.join(os.path.dirname(sys.argv[0]),'v2ray.exe'), 'run'], 
        input=config, 
        text=True
    )


if __name__ == '__main__':
    config = read_conf(os.path.join(os.path.dirname(sys.argv[0]),'nessus-update.conf'))
    if not test_conf(config):
        os.system('pause')
        sys.exit(1)

    # 使用离线文件时，检查其plugin_set版本
    config['local'] ={'path': '', 'plugin_set': ''}
    if len(sys.argv) == 2:
        config['local']['path'] = sys.argv[1]
    elif os.path.exists(os.path.join(os.path.dirname(sys.argv[0]), 'all-2.0.tar.gz')):
        config['local']['path'] = os.path.join(os.path.dirname(sys.argv[0]), 'all-2.0.tar.gz')
    if config['local']['path']:
        print('[Info] 检查本地文件有效性...')
        try:
            with tarfile.open(config['local']['path'], 'r:gz') as f:
                with f.extractfile('plugin_feed_info.inc') as info:
                    while True:
                        line = info.readline().decode('utf-8')
                        if not line:
                            break
                        if 'PLUGIN_SET' in line:
                            config['local']['plugin_set'] = line.split('"')[1]
                            break
            assert config['local']['plugin_set']
            print(' -> 文件有效，特征库版本 (plugin_set) = {}'.format(config['local']['plugin_set']))
        except:
            print(' -> 文件无效')
            traceback.print_exc(limit=1)

    # 将所有plugin_set格式化成datetime形式
    if config['nessus']['plugin_set']:
        current_datetime = datetime.datetime.strptime(config['nessus']['plugin_set'], '%Y%m%d%H%M')
    else:
        current_datetime = datetime.datetime.fromtimestamp(0)
    if config['local']['plugin_set']:
        local_datetime = datetime.datetime.strptime(config['local']['plugin_set'], '%Y%m%d%H%M')
    else:
        local_datetime = datetime.datetime.fromtimestamp(0)
    if config['oss']['plugin_set']:
        remote_datetime = datetime.datetime.strptime(config['oss']['plugin_set'], '%Y%m%d%H%M')
    else:
        remote_datetime = datetime.datetime.fromtimestamp(0)

    if current_datetime >= max(local_datetime, remote_datetime):
        print('[Info] 启动在线更新...')
        start_v2ray(config['v2ray']['json'])
        os.system('pause')
        sys.exit(0)

    # 触发oss下载需满足的条件：
    # - oss距离当前时间差异小于15天；
    # - oss距离现有特征库差异大于15天；
    if (datetime.datetime.now() - remote_datetime <= datetime.timedelta(days=15) and 
        remote_datetime - current_datetime > datetime.timedelta(days=15)):
        result = input(' -> 是否从OSS缓存下载特征库{}({}MB)？（Y/n）'.format(
            config['oss']['plugin_set'], 
            config['oss']['size'][:-6]
            ))
        if result.lower() != 'n':
            print(' -> 下载中...')
            r = requests.get(config['oss']['url'], stream=True)
            progress_bar = tqdm(total=int(config['oss']['size']), unit='iB', unit_scale=True, desc='all-2.0.tar.gz')
            with open(config['local']['path'] + '.tmp', 'wb') as file:
                for data in r.iter_content(4096):
                    progress_bar.update(len(data))
                    file.write(data)
            progress_bar.close()
            if qiniu.etag(config['local']['path'] + '.tmp') == config['oss']['etag']:
                shutil.move(config['local']['path'] + '.tmp', config['local']['path'])
                local_datetime = remote_datetime
                config['local']['plugin_set'] = config['oss']['plugin_set']
            else:
                print(' -> [Warning] Etag校验失败')
                os.remove(config['local']['path'] + '.tmp')

    # 触发本地更新需满足的条件：
    # - 离线文件距离现有特征库差异大于0；
    # - 离线文件距离当前时间差异小于30天；
    if (local_datetime > current_datetime and 
        datetime.datetime.now() - local_datetime < datetime.timedelta(days=30)):
        upload(config['local'], config['nessus'])
        os.system('pause')
        sys.exit(0)

    # 均不满足时启动在线更新
    print('[Info] 启动在线更新...')
    start_v2ray(config['v2ray']['json'])
    os.system('pause')
    sys.exit(0)