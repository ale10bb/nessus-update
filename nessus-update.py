# -*- coding: UTF-8 -*-
import os, shutil
import logging
import datetime
import qiniu
from tqdm import tqdm
import traceback
from packaging import version

# session用于和 nessus scanner 之间的通信
import requests
import xml.etree.ElementTree as ET
# 去除nessus自签名证书的警告
requests.packages.urllib3.disable_warnings()


def read_conf(conf_path: str) -> dict:
    ''' 读取配置文件

    Args:
        conf_path(str): 配置文件路径

    Return:
        {
            'nessus': {'username': 'xxx', 'password': 'xxx', 'host': '127.0.0.1'},
            'v2ray': {'address': 'nessus-update.chenql.cn', 'port': 8835, 'user': 'xxx'},
            'oss': {'url': 'http://static.chenql.cn/nessus/all-2.0.tar.gz'},
            'local': {'path': 'all-2.0.tar.gz'},
        }
    '''
    ret = {
        'nessus': {'username': 'xxx', 'password': 'xxx', 'host': '127.0.0.1'},
        'v2ray': {'address': 'nessus-update.chenql.cn', 'port': 8835, 'user': 'xxx', 'host': '127.0.0.1'},
        'oss': {'url': 'http://static.chenql.cn/nessus/all-2.0.tar.gz'},
        'local': {'path': 'all-2.0.tar.gz'},
    }  

    # 配置文件必须存在且内容必须合法
    logging.info('读取配置...')
    from configparser import ConfigParser
    import socket
    try:
        if not os.path.exists(conf_path):
            logging.warning('"nessus-update.conf"不存在，写入默认配置')
            with open(conf_path, 'w') as f:
                f.write('[nessus]\n')
                f.write('username    =   xxx\n')
                f.write('password    =   xxx\n')
                f.write('host        =   127.0.0.1\n')
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

        ret['nessus']['username'] = config.get('nessus', 'username', fallback='xxx')
        ret['nessus']['password'] = config.get('nessus', 'password', fallback='xxx')
        ret['nessus']['host'] = config.get('nessus', 'host', fallback='127.0.0.1')
        logging.debug('nessus.username: %s', ret['nessus']['username'])
        logging.debug('nessus.password: %s', ret['nessus']['password'])
        logging.debug('nessus.host: %s', ret['nessus']['host'])

        ret['v2ray']['address'] = config.get('v2ray', 'address', fallback='nessus-update.chenql.cn')
        ret['v2ray']['port'] = config.getint('v2ray', 'port', fallback=8835)
        ret['v2ray']['user'] = config.get('v2ray', 'user', fallback='xxx')
        ret['v2ray']['host'] = socket.gethostbyname(ret['nessus']['host'])
        logging.debug('v2ray.address: %s', ret['v2ray']['address'])
        logging.debug('v2ray.port: %s', ret['v2ray']['port'])
        logging.debug('v2ray.user: %s', ret['v2ray']['user'])
        logging.debug('v2ray.host: %s', ret['v2ray']['host'])
        
        ret['oss']['url'] = config.get('oss', 'url', fallback='http://static.chenql.cn/nessus/all-2.0.tar.gz')
        logging.debug('oss.url: %s', ret['oss']['url'])
    except:
        logging.error('读取配置文件失败\n%s', traceback.format_exc(limit=1))

    return ret


def test_nessus(config: dict) -> bool:
    ''' 测试[nessus]配置是否有效，有效时将在config中写入plugin_set键

    Args:
        config: {'username': 'xxx', 'password': 'xxx', 'host': 'xxx'}

    Return:
        True/False
    '''
    logging.debug('args: %s', config)

    logging.info('检查nessus配置...')
    try:
        session = requests.session()
        base_url = f"https://{config['host']}:8834"
        logging.info('连接目标: %s', base_url)
        session.headers.update({'User-Agent': 'SecurityCenter/0.0.0'})
        session.verify = False
        # 无法连接或登录失败时终止验证
        r = session.get(f"{base_url}/feed")
        r.raise_for_status()
        logging.debug('r: (%s)\n%s', r.status_code, r.text)
        current_version = ET.fromstring(r.text).find('./contents/server_version').text
        logging.info('客户端版本: %s', current_version)
        # 获取最新客户端版本
        try:
            data = requests.get('https://www.tenable.com/downloads/api/v2/pages/nessus').json()
            versions = [version.parse(item[9:]) for item in data['releases']['latest'].keys()]
            if version.parse(current_version) < max(versions):
                logging.warning('检测到新版本Nessus客户端<%s>，可自行下载安装: https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-latest-x64.msi', str(max(versions)))
        except:
            pass

        r = session.post(f"{base_url}/login", 
            data={'login': config['username'], 'password': config['password'], 'seq': 1},
        )
        logging.debug('r: (%s)\n%s', r.status_code, r.text)
        r.raise_for_status()

        # 从Scanner中读取当前插件版本
        login_xml = ET.fromstring(r.text)
        token = login_xml.find('./contents/token').text
        # 未注册的新scanner的plugin_set标签值为空(None)
        config['plugin_set'] = login_xml.find('./contents/plugin_set').text
        logging.info('特征库版本: <%s>', config['plugin_set'])
        r = session.post(f"{base_url}/logout", 
            files={'seq': (None, 2), 'token': (None, token)},
        )
        logging.debug('r: (%s)\n%s', r.status_code, r.text)
        r.raise_for_status()

        return True
    except:
        logging.error('Nessus Scanner 连接/登录失败\n%s', traceback.format_exc(limit=1))
        return False


def test_oss(config:dict) -> bool:
    ''' 测试[oss]配置是否有效，有效时将在config中写入size/etag/plugin_set键

    Args:
        config: {'url': 'xxx'}

    Return:
        True/False
    '''
    logging.debug('args: %s', config)

    logging.info('检查OSS配置...')
    try:
        logging.info('文件路径: %s', config['url'])
        r = requests.head(config['url'])
        logging.debug('r: (%s)\n%s', r.status_code, r.headers)
        r.raise_for_status()

        config['size'] = r.headers['Content-Length']
        config['etag'] = r.headers['Etag'][1:-1]
        config['plugin_set'] = r.headers['X-Qn-Meta-Plugin-Set']
        logging.info('特征库版本: <%s>', config['plugin_set'])
        return True
    except:
        logging.warning('OSS连接失败/非法的URL\n%s', traceback.format_exc(limit=1))
        return False


def test_local(config:dict) -> bool:
    ''' 测试离线文件是否有效，有效时将在config中写入plugin_set键

    Args:
        config: {'path': 'xxx'}

    Return:
        True/False
    '''
    logging.debug('args: %s', config)

    logging.info('检查本地文件有效性...')
    try:
        import tarfile
        with tarfile.open(config['path'], 'r:gz') as f:
            with f.extractfile('plugin_feed_info.inc') as info:
                while True:
                    line = info.readline().decode('utf-8')
                    if not line:
                        break
                    if 'PLUGIN_SET' in line:
                        config['plugin_set'] = line.split('"')[1]
                        break
        assert config['plugin_set'], 'empty PLUGIN_SET'
        logging.info('特征库版本: <%s>', config['plugin_set'])
        return True
    except:
        logging.warning('文件无效\n%s', traceback.format_exc(limit=1))
        return False


def start_offline(config_nessus, config_local):
    ''' 使用本地完整包更新Scanner

    Args:
        config_nessus(dict): Scanner配置信息
        config_local(dict): 本地完整包信息
    '''
    logging.debug('args: %s', {'config_nessus': config_nessus, 'config_local': config_local})

    logging.info('使用本地文件更新Scanner...')
    logging.info('特征库版本: <%s>', config_local['plugin_set'])
    try:
        session = requests.session()
        base_url = f"https://{config_nessus['host']}:8834"
        session.headers.update({'User-Agent': 'SecurityCenter/0.0.0'})
        session.verify = False
        logging.info('seq_1 (login)')
        r = session.post(f"{base_url}/login", 
            data={
                'login': config_nessus['username'], 
                'password': config_nessus['password'], 
                'seq': 1,
            }
        )
        logging.debug('r: (%s)\n%s', r.status_code, r.text)
        r.raise_for_status()
        token = ET.fromstring(r.text).find('./contents/token').text

        logging.info('seq_2 (upload)')
        with open(config_local['path'],'rb') as f:
            r = session.post(f"{base_url}/file/upload", 
                files={
                    'token': (None, token), 
                    'seq': (None, 2), 
                    'Filedata': (config_local['path'], f),
                }
            )
            logging.debug('r: (%s)\n%s', r.status_code, r.text)
            r.raise_for_status()

        logging.info('seq_3 (process)')
        r = session.post(f"{base_url}/plugins/process", 
            files={
                'token': (None, token), 
                'seq': (None, 3), 
                'filename': (None, config_local['path']),
            }
        )
        logging.debug('r: (%s)\n%s', r.status_code, r.text)
        r.raise_for_status()

        logging.info('seq_4 (logout)')
        r = session.post(f"{base_url}/logout", 
            files={'seq': (None, 4), 'token': (None, token)}
        )
        logging.debug('r: (%s)\n%s', r.status_code, r.text)
        r.raise_for_status()
        logging.info('上传成功，请等待nessusd更新后自动重启')
    except:
        logging.error('上传失败\n%s', traceback.format_exc(limit=1))


def start_online(config: dict):
    ''' 启动在线更新 (v2ray)

    Args:
        config: {'address': 'xxx', 'port': xxx, 'user': 'xxx', host: 'xxx'}
    '''
    logging.debug('args: %s', config)
    v2ray_json = {
        'log': {'loglevel': 'warning'},
        'dns': {'hosts': {'nessus.local': config['host']}},
        'reverse': {
            'bridges': [
                {'tag': 'bridge', 'domain': f"{config['user']}.nessus-tunnel"}
            ]
        },
        'outbounds': [
            {
                'tag': 'toProxy',
                'protocol': 'vmess',
                'settings': {
                    'vnext': [{
                        'address': config['address'],
                        'port': config['port'],
                        'users': [{'id': '1b73a61f-29b3-4633-a804-53c371e48e75', 'security': 'auto'}]
                    }]
                }
            },
            {'tag': 'direct', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIP'}}
        ],
        'routing': {
            'rules': [
                {
                    'type': 'field',
                    'inboundTag': ['bridge'],
                    'domain': [f"full:{config['user']}.nessus-tunnel"],
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
    import json
    import subprocess
    try:
        p = subprocess.run(['v2ray.exe', 'version'], check=True , capture_output=True)
        logging.debug('stdout: \n%s', p.stdout.decode('utf-8'))
    except:
        logging.error('启动失败\n%s', traceback.format_exc(limit=1))
        return

    logging.info('启动在线更新...')
    subprocess.run(
        ['v2ray.exe', 'run'], 
        input=json.dumps(v2ray_json), 
        text=True
    )


def init_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - [%(levelname)s] - %(funcName)s:%(lineno)d -> %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename='nessus-update.log', 
        encoding='utf-8'
    )

    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter(
        fmt='%(asctime)s - [%(levelname)s] -> %(message)s',
        datefmt='%H:%M:%S'
    ))
    ch.setLevel(logging.INFO)
    logging.getLogger('').addHandler(ch)


if __name__ == '__main__':
    import platform
    import nuitka.Version
    print('*******************************************')
    print('          Nessus Scanner 更新工具          ')
    print('          - v2.2.1-{}-{}'.format(
        platform.python_version(), 
        nuitka.Version.getNuitkaVersion()
    ))
    print('*******************************************')
    print('')

    import sys
    os.chdir(os.path.dirname(os.path.join(os.getcwd(), sys.argv[0])))
    init_logging()
    logging.debug('cwd: %s', os.getcwd())

    config = read_conf('nessus-update.conf')
    # nessus服务端必须有效
    if not test_nessus(config['nessus']):
        os.system('pause')
        sys.exit(1)
    # OSS可选
    test_oss(config['oss'])
    # 本地文件可选
    if os.path.exists(config['local']['path']):
        test_local(config['local'])

    # 将所有plugin_set格式化成datetime形式
    for section in ['nessus', 'local', 'oss']:
        if config[section].get('plugin_set'):
            config[section]['datetime'] = datetime.datetime.strptime(config[section]['plugin_set'], '%Y%m%d%H%M')
        else:
            config[section]['datetime'] = datetime.datetime.fromtimestamp(0)
        logging.debug('%s.datetime: %s', section, config[section]['datetime'])

    # scanner 特征库超过缓存时，直接进入在线更新模式
    if config['nessus']['datetime'] >= max(config['local']['datetime'], config['oss']['datetime']):
        start_online(config['v2ray'])
        os.system('pause')
        sys.exit(0)

    # 触发oss下载需满足的条件：
    # - oss距离当前时间差异小于15天；
    # - oss距离现有特征库差异大于15天；
    # - oss距离离线文件差异大于0；
    if (datetime.datetime.now() - config['oss']['datetime'] <= datetime.timedelta(days=15) and 
        config['oss']['datetime'] - config['nessus']['datetime'] > datetime.timedelta(days=15) and
        config['oss']['datetime'] > config['local']['datetime']):
        logging.debug('enter download')
        result = input(' -> 是否从OSS缓存下载特征库<{}> ({:,}KB)？（Y/n）'.format(
            config['oss']['plugin_set'], 
            int(config['oss']['size']) // 1024,
        ))
        if result.lower() != 'n':
            logging.info('下载中...')
            r = requests.get(config['oss']['url'], stream=True)
            progress_bar = tqdm(total=int(config['oss']['size']), unit='iB', unit_scale=True, desc='all-2.0.tar.gz')
            with open('all-2.0.tar.gz.tmp', 'wb') as file:
                for data in r.iter_content(4096):
                    progress_bar.update(len(data))
                    file.write(data)
            progress_bar.close()
            if qiniu.etag('all-2.0.tar.gz.tmp') == config['oss']['etag']:
                shutil.move('all-2.0.tar.gz.tmp', 'all-2.0.tar.gz')
                config['local']['datetime'] = config['oss']['datetime']
                logging.debug('local: %s', config['local']['datetime'])
                config['local']['plugin_set'] = config['oss']['plugin_set']
            else:
                logging.warning('Etag校验失败')
                os.remove('all-2.0.tar.gz.tmp')

    # 触发本地更新需满足的条件：
    # - 离线文件距离现有特征库差异大于0；
    # - 离线文件距离当前时间差异小于30天；
    if (config['local']['datetime'] > config['nessus']['datetime'] and 
        datetime.datetime.now() - config['local']['datetime'] < datetime.timedelta(days=30)):
        start_offline(config['nessus'], config['local'])
        os.system('pause')
        sys.exit(0)

    # 均不满足时启动在线更新
    start_online(config['v2ray'])
    os.system('pause')
    sys.exit(0)
