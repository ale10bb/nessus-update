# -*- coding: UTF-8 -*-
from configparser import ConfigParser
import os, shutil, sys
import logging
import datetime
import tarfile
import qiniu
from tqdm import tqdm
import traceback

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
            'nessus': {'username': 'xxx', 'password': 'xxx', 'host': 'xxx', 'plugin_set': 'xxx'}, 
            'v2ray': {'json': ''},
            'oss': {'url': '', 'size': '', 'etag': '', 'plugin_set': ''},
        }
    '''
    logger = logging.getLogger('read_conf()')
    import json
    ret = {
        'nessus': {'username': '', 'password': '', 'host': '', 'plugin_set': ''},
        'v2ray': {'json': ''},
        'oss': {'url': '', 'size': '', 'etag': '', 'plugin_set': ''},
    }  

    # 配置文件必须存在且内容必须合法
    logger.info('读取配置...')
    try:
        if not os.path.exists(conf_path):
            logger.warning('nessus-update.conf不存在，写入默认配置')
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

        ret['nessus']['username'] = config.get('nessus', 'username', fallback='username')
        ret['nessus']['password'] = config.get('nessus', 'password', fallback='password')
        ret['nessus']['host'] = config.get('nessus', 'host', fallback='127.0.0.1')
        logger.debug('nessus.user: {}'.format(ret['nessus']['username']))
        logger.debug('nessus.host: {}'.format(ret['nessus']['host']))

        v2ray_json = {
            'log': {'loglevel': 'warning'},
            'dns': {'hosts': {'nessus.local': ret['nessus']['host']}},
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
                            'port': config.getint('v2ray', 'port', fallback=8835),
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
        logger.debug('v2ray.address: {}'.format(config.get('v2ray', 'address', fallback='nessus-update.chenql.cn')))
        logger.debug('v2ray.port: {}'.format(config.getint('v2ray', 'port', fallback=8835)))
        logger.debug('v2ray.bridge: {}'.format(config.get('v2ray', 'user', fallback='placeholder')))
        ret['v2ray']['json'] = json.dumps(v2ray_json)
        
        ret['oss']['url'] = config.get('oss', 'url', fallback='http://static.chenql.cn/nessus/all-2.0.tar.gz')
        logger.debug('oss.url: {}'.format(ret['oss']['url']))
    except:
        logger.error('读取配置文件失败\n{}'.format(traceback.format_exc(limit=1)))

    return ret


def test_conf(config:dict) -> bool:
    ''' 测试配置是否有效

    Args:
        conf_path(str): 配置文件路径

    Return:
        True/False
    '''
    logger = logging.getLogger('test_conf()')
    logger.debug('args: {}'.format(config))

    # nessus服务端必须有效
    logger.info('检查nessus配置...')
    try:
        session = requests.session()
        base_url = 'https://{}:8834'.format(config['nessus']['host'])
        logger.info('连接目标: {}'.format(base_url))
        session.headers.update({'User-Agent': 'SecurityCenter/0.0.0'})
        session.verify = False
        # 无法连接或登录失败时终止验证
        r = session.get('{}/feed'.format(base_url))
        r.raise_for_status()
        logger.debug('r: ({})\n{}'.format(r.status_code, r.text))
        logger.info('客户端版本: {}'.format(ET.fromstring(r.text).find('./contents/server_version').text))

        r = session.post(
            '{}/login'.format(base_url), 
            data={'login': config['nessus']['username'], 'password': config['nessus']['password'], 'seq': 1}
        )
        logger.debug('r: ({})\n{}'.format(r.status_code, r.text))
        r.raise_for_status()

        # 从Scanner中读取当前插件版本
        login_xml = ET.fromstring(r.text)
        token = login_xml.find('./contents/token').text
        # 未注册的新scanner的plugin_set标签值为空(None)
        config['nessus']['plugin_set'] = login_xml.find('./contents/plugin_set').text
        if not config['nessus']['plugin_set']:
            config['nessus']['plugin_set'] = ''
            logger.info('特征库版本: <null> (unregistered scanner)')
        else:
            logger.info('特征库版本: <{}>'.format(config['nessus']['plugin_set']))
        r = session.post(
            '{}/logout'.format(base_url), 
            files={'seq': (None, 2), 'token': (None, token)}
        )
        logger.debug('r: ({})\n{}'.format(r.status_code, r.text))
        r.raise_for_status()
    except:
        logger.error('Nessus Scanner 连接/登录失败\n{}'.format(traceback.format_exc(limit=1)))

    logger.info('检查OSS配置...')
    try:
        logger.info('文件路径: {}'.format(config['oss']['url']))
        r = requests.head(config['oss']['url'])
        logger.debug('r: ({})\n{}'.format(r.status_code, r.headers))
        r.raise_for_status()
        config['oss']['size'] = r.headers['Content-Length']
        config['oss']['etag'] = r.headers['Etag'][1:-1]
        config['oss']['plugin_set'] = r.headers['X-Qn-Meta-Plugin-Set']
        logger.info('特征库版本: <{}>'.format(config['oss']['plugin_set']))
    except:
        config['oss']['plugin_set'] = ''
        logger.warning('OSS连接失败/非法的URL\n{}'.format(traceback.format_exc(limit=1)))

    return True


def upload(local_file_info, scanner_info):
    ''' 使用本地完整包更新Scanner

    Args:
        local_file_info(dict): 本地完整包信息
        scanner_info(dict): Scanner配置信息
    '''
    logger = logging.getLogger('upload()')
    logger.debug('args: {}'.format({'local_file': local_file_info, 'scanner': scanner_info}))

    logger.info('使用本地文件更新Scanner...')
    logger.info('特征库版本: <{}>'.format(local_file_info['plugin_set']))
    try:
        session = requests.session()
        base_url = 'https://{}:8834'.format(scanner_info['host'])
        session.headers.update({'User-Agent': 'SecurityCenter/0.0.0'})
        session.verify = False
        logger.info('seq_1 (login)')
        r = session.post(
            '{}/login'.format(base_url), 
            data={'login': scanner_info['username'], 'password': scanner_info['password'], 'seq': 1}
        )
        logger.debug('r: ({})\n{}'.format(r.status_code, r.text))
        r.raise_for_status()
        token = ET.fromstring(r.text).find('./contents/token').text

        logger.info('seq_2 (upload)')
        with open('all-2.0.tar.gz','rb') as f:
            r = session.post(
                '{}/file/upload'.format(base_url), 
                files={'token': (None, token), 'seq': (None, 2), 'Filedata': ('all-2.0.tar.gz', f)}
            )
            r.raise_for_status()

        logger.info('seq_3 (process)')
        r = session.post(
            '{}/plugins/process'.format(base_url), 
            files={'token': (None, token), 'seq': (None, 3), 'filename': (None, 'all-2.0.tar.gz')}
        )
        logger.debug('r: ({})\n{}'.format(r.status_code, r.text))
        r.raise_for_status()

        logger.info('seq_4 (logout)')
        r = session.post(
            '{}/logout'.format(base_url), 
            files={'seq': (None, 4), 'token': (None, token)}
        )
        logger.debug('r: ({})\n{}'.format(r.status_code, r.text))
        r.raise_for_status()
        logger.info('上传成功，请等待nessusd更新后自动重启')
    except:
        logger.error('上传失败\n{}'.format(traceback.format_exc(limit=1)))


def start_v2ray(config: str):
    logger = logging.getLogger('start_v2ray()')
    logger.debug('args: {}'.format({'config': config}))
    import subprocess
    try:
        p = subprocess.run(['v2ray.exe', 'version'], check=True , capture_output=True)
        logger.debug('stdout: \n{}'.format(p.stdout.decode('utf-8')))
    except:
        logger.error('启动失败\n{}'.format(traceback.format_exc(limit=1)))
        return

    subprocess.run(
        ['v2ray.exe', 'run'], 
        input=config, 
        text=True
    )


def init_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - [%(levelname)s] - %(name)s -> %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename='nessus-update.log', 
        encoding='utf-8'
    )

    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter(
        fmt='%(asctime)s - [%(levelname)s] - %(name)s -> %(message)s',
        datefmt='%H:%M:%S'
    ))
    ch.setLevel(logging.INFO)
    logging.getLogger('').addHandler(ch)


if __name__ == '__main__':
    print('*******************************************')
    print('          Nessus Scanner 更新工具          ')
    print('                         - v2.1.1          ')
    print('*******************************************')
    print('')

    os.chdir(os.path.dirname(sys.argv[0]))
    init_logging()
    logger = logging.getLogger('nessus-update')
    logger.debug('cwd: {}'.format(os.getcwd()))

    config = read_conf('nessus-update.conf')
    if not test_conf(config):
        os.system('pause')
        sys.exit(1)

    # 使用离线文件时，检查其plugin_set版本
    config['local'] ={'plugin_set': ''}
    if os.path.exists('all-2.0.tar.gz'):
        logger.info('检查本地文件有效性...')
        try:
            with tarfile.open('all-2.0.tar.gz', 'r:gz') as f:
                with f.extractfile('plugin_feed_info.inc') as info:
                    while True:
                        line = info.readline().decode('utf-8')
                        if not line:
                            break
                        if 'PLUGIN_SET' in line:
                            config['local']['plugin_set'] = line.split('"')[1]
                            break
            assert config['local']['plugin_set']
            logger.info('特征库版本: <{}>'.format(config['local']['plugin_set']))
        except:
            logger.warning('文件无效\n{}'.format(traceback.format_exc(limit=1)))

    # 将所有plugin_set格式化成datetime形式
    if config['nessus']['plugin_set']:
        current_datetime = datetime.datetime.strptime(config['nessus']['plugin_set'], '%Y%m%d%H%M')
    else:
        current_datetime = datetime.datetime.fromtimestamp(0)
    logger.debug('current: {}'.format(current_datetime))
    if config['local']['plugin_set']:
        local_datetime = datetime.datetime.strptime(config['local']['plugin_set'], '%Y%m%d%H%M')
    else:
        local_datetime = datetime.datetime.fromtimestamp(0)
    logger.debug('local: {}'.format(local_datetime))
    if config['oss']['plugin_set']:
        remote_datetime = datetime.datetime.strptime(config['oss']['plugin_set'], '%Y%m%d%H%M')
    else:
        remote_datetime = datetime.datetime.fromtimestamp(0)
    logger.debug('remote: {}'.format(remote_datetime))

    if current_datetime >= max(local_datetime, remote_datetime):
        logger.info('启动在线更新...')
        start_v2ray(config['v2ray']['json'])
        os.system('pause')
        sys.exit(0)

    # 触发oss下载需满足的条件：
    # - oss距离当前时间差异小于15天；
    # - oss距离现有特征库差异大于15天；
    # - oss距离离线文件差异大于0；
    if (datetime.datetime.now() - remote_datetime <= datetime.timedelta(days=15) and 
        remote_datetime - current_datetime > datetime.timedelta(days=15) and
        remote_datetime > local_datetime):
        logger.debug('enter download')
        result = input(' -> 是否从OSS缓存下载特征库<{}> ({:,}KB)？（Y/n）'.format(
            config['oss']['plugin_set'], 
            int(config['oss']['size']) // 1024,
        ))
        if result.lower() != 'n':
            logger.info('下载中...')
            r = requests.get(config['oss']['url'], stream=True)
            progress_bar = tqdm(total=int(config['oss']['size']), unit='iB', unit_scale=True, desc='all-2.0.tar.gz')
            with open('all-2.0.tar.gz.tmp', 'wb') as file:
                for data in r.iter_content(4096):
                    progress_bar.update(len(data))
                    file.write(data)
            progress_bar.close()
            if qiniu.etag('all-2.0.tar.gz.tmp') == config['oss']['etag']:
                shutil.move('all-2.0.tar.gz.tmp', 'all-2.0.tar.gz')
                local_datetime = remote_datetime
                logger.debug('local: {}'.format(local_datetime))
                config['local']['plugin_set'] = config['oss']['plugin_set']
            else:
                logger.warning('Etag校验失败')
                os.remove('all-2.0.tar.gz.tmp')

    # 触发本地更新需满足的条件：
    # - 离线文件距离现有特征库差异大于0；
    # - 离线文件距离当前时间差异小于30天；
    if (local_datetime > current_datetime and 
        datetime.datetime.now() - local_datetime < datetime.timedelta(days=30)):
        upload(config['local'], config['nessus'])
        os.system('pause')
        sys.exit(0)

    # 均不满足时启动在线更新
    logger.info('启动在线更新...')
    start_v2ray(config['v2ray']['json'])
    os.system('pause')
    sys.exit(0)
