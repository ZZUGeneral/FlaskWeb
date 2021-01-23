# -*- coding: utf-8 -*-
# @Time    : 2020/12/23 17:58
# @Author  : yanghelong
# @File    : nmap.py
# @Software: PyCharm

"""
nmap.py - version and date, see below

Source code : https://bitbucket.org/xael/python-nmap

Author :

* Alexandre Norman - norman at xael.org

Contributors:

* Steve 'Ashcrow' Milner - steve at gnulinux.net
* Brian Bustin - brian at bustin.us
* old.schepperhand
* Johan Lundberg
* Thomas D. maaaaz
* Robert Bost
* David Peltier

Licence: GPL v3 or any later version for python-nmap


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


**************
IMPORTANT NOTE
**************

The Nmap Security Scanner used by python-nmap is distributed
under it's own licence that you can find at https://svn.nmap.org/nmap/COPYING

Any redistribution of python-nmap along with the Nmap Security Scanner
must conform to the Nmap Security Scanner licence

"""

import csv
import io
import os
import re
import shlex
import subprocess
import sys
from xml.etree import ElementTree as ET

try:
    from multiprocessing import Process
except ImportError:
    from threading import Thread as Poocess

__author__ = 'Yhl'
__version__ = '0.0.1'
__last_modification__ = '2018/09/23'


############################################################################
class PortScanner(object):

    # 初始化，确认存在 nmap  可以使用
    def __init__(self, nmap_search_path=('nmap', '/usr/bin/nmap',
                                         '/usr/local/bin/nmap',
                                         '/sw/bin/nmap', '/opt/local/bin/nmap')):
        """
            Initialize PortScanner module

            * detects nmap on the system and nmap version
            * may raise PortScannerError exception if nmap is not found in the path

            :param nmap_search_path: tupple of string where to search for nmap executable. Change this if you want to use a specific version of nmap.
            :returns: nothing

        """
        self._namp_path = ''
        self._scan_result = {}
        self._nmap_version_number = 0
        self._nmap_subversion_number = 0
        self._nmap_last_output = ''
        is_nmap_found = False

        # 匹配 namp -V 的结果，判断是否存在 nmap (http or https)
        regex = re.compile(
            'Nmap version [0-9]*\.[0-9]*[^ ]* \( http(|s)://.* \)'
        )
        # 根据不同系统，确定不同的nmap启动方式
        for namp_path in nmap_search_path:
            try:
                if sys.platform.startswith('freebsd') \
                        or sys.platform.startswith('linux') \
                        or sys.platform.startswith('daewin'):
                    p = subprocess.Popen([namp_path, '-V'], bufsize=10000, stdout=subprocess.PIPE, close_fds=True)
                else:
                    p = subprocess.Popen([namp_path, '-V'], bufsize=10000, stdout=subprocess.PIPE)
            except OSError:
                pass
            else:
                self._namp_path = namp_path  # 保存namp位置
                break
        else:
            raise PortScannerError('nmap program was not found in path. Path is {0}'.format(os.getenv('PATH')))

        self._nmap_last_output = bytes.decode(p.communicate()[0])  # 保存 nmap -V 的结果
        # os.linesep字符串给出当前平台使用的行终止符
        for line in self._nmap_last_output.split(os.linesep):
            if regex.match(line) is not None:
                is_nmap_found = True
                # 获取版本号的正则表达式
                regex_version = re.compile('[0-9]+')
                regex_subversion = re.compile('\.[0-9]+')

                rv = regex_version.match(line)
                rsv = regex_subversion.match(line)

                if rv is not None and rsv is not None:
                    # 获取版本号
                    self._namp_version_number = int(line[rv.start():rv.end()])
                    self._namp_subversion_number = int(line[rsv.start():rsv.end()])
                break
        if not is_nmap_found:
            raise PortScannerError('nmap program was not found in path')

    # 返回 nmap 扫描结果
    def get_namp_last_output(self):
        return self._nmap_last_output

    # 返回 nmap 的版本号
    def namp_version(self):
        return (self._namp_version_number, self._namp_subversion_number)

    # 不扫描但解析目标主机并返回主机列表
    def listscan(self, hosts='127.0.0.1'):
        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
        output = self.scan(hosts, arguments='-sL')
        # 判断目标主机是不是 IPv6
        if 'scaninfo' in output['nmap'] \
                and 'error' in output['nmap']['scaninfo'] \
                and len(output['namp']['scaninfo']['error']) > 0 \
                and 'looks like an IPv6 target specification' in output['nmap']['scaninfo']['eror'][0]:
            self.scan(hosts, arguments='-sL -6')
        return self.all_hosts()

    # nmap 扫描指定的主机
    def scan(self, hosts='127.0.0.1', ports=None, arguments='-St', sudo=False):
        '''
        :param hosts: 主机列表
        :param ports: 指定端口
        :param arguments: nmap扫描参数
        :param sudo: 使用管理员权限
        :return: 以字典形式返回扫描结果
        '''

        # 判断主机列表是否是字符串，即是否规范
        if sys.version_info[0] == 2:
            assert type(hosts) in (str, type(None)), 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
            assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))  # noqa
            assert type(arguments) in (str, type(None)), 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))  # noqa
        else:
            assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
            assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))  # noqa
            assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))  # noqa

        for redirecting_output in ['-oX', '-oA']:
            assert redirecting_output not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'  # noqa

        h_args = shlex.split(hosts)
        f_args = shlex.split(arguments)

        # 加载扫描
        args = [self._namp_path, '-oX', '-'] + h_args + ['-p', ports] * (ports is not None) + f_args
        if sudo:
            args = ['sudo'] + args

        p = subprocess.Popen(args, bufsize=10000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # 等待扫描结束
        (self._nmap_last_output, nmap_err) = p.communicate()
        self._nmap_last_output = bytes.decode(self._nmap_last_output)
        nmap_err = bytes.decode(nmap_err)

        # 扫描出错处理
        nmap_err_keep_trace = []
        nmap_warn_keep_trace = []
        if len(nmap_err) > 0:
            regex_warning = re.compile('^Warning: .*', re.IGNORECASE)
            for line in nmap_err.split(os.linesep):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        nmap_warn_keep_trace.append(line + os.linesep)
                    else:
                        nmap_err_keep_trace.append(nmap_err)

        return self.analyse_namp_xml_scan(
            nmap_xml_output=self._nmap_last_outputm,
            nmap_err=nmap_err,
            nmap_err_keep_trace=nmap_err_keep_trace,
            nmap_warn_keep_trace=nmap_warn_keep_trace
        )

    '''
    分析 nmap xml格式 的扫描结果
    '''

    def analyse_nmap_xml_scan(self, nmap_xml_output=None, nmap_err='', nmap_err_keep_trace='', nmap_warn_keep_trace=''):
        if nmap_xml_output == None:
            self._nmap_last_output = nmap_xml_output
        scan_result = {}

        try:
            dom = ET.fromstring(self._nmap_last_output)
        except Exception:
            if len(nmap_err) > 0:
                raise PortScannerError(nmap_err)
            else:
                raise PortScannerError(self._nmap_last_output)

        scan_result['nmap'] = {
            'command_line': dom.get('args'),
            'scan_info': {},
            'scanstats': {
                'timestr': dom.find("runstats/finished").get('timestr'),
                'elapsed': dom.find("runstats/finished").get('elapsed'),
                'uphosts': dom.find("runstats/hosts").get('up'),
                'downhosts': dom.find("runstats/hosts").get('down'),
                'totalhosts': dom.find("runstats/hosts").get('total')
            }
        }

        if len(nmap_err_keep_trace) > 0:
            scan_result['nmap']['scan_info']['error'] = nmap_err_keep_trace

        if len(nmap_warn_keep_trace) > 0:
            scan_result['nmap']['scan_info']['warning'] = nmap_warn_keep_trace
        for dsci in dom.findall('scaninfo'):
            scan_result['nmap']['scaninfo'][dsci.get('protocol')] = {
                'method': dsci.get('type'),
                'services': dsci.get('services')
            }

        scan_result['scan'] = {}

        for dhost in dom.findall('host'):
            # host ip, mac and other addresses
            host = None
            address_block = {}
            vendor_block = {}
            for address in dhost.findall('address'):
                addtype = address.get('addrtype')
                address_block[addtype] = address.get('addr')
                if addtype == 'ipv4':
                    host = address_block[addtype]
                elif addtype == 'mac' and address.get('vendor') is not None:
                    vendor_block[address_block[addtype]] = address.get('vendor')

            if host is None:
                host = dhost.find('address').get('addr')

            hostnames = []
            if len(dhost.findall('hostnames/hostname')) > 0:
                for dhostname in dhost.findall('hostnames/hostname'):
                    hostnames.append({
                        'name': dhostname.get('name'),
                        'type': dhostname.get('type'),
                    })
            else:
                hostnames.append({
                    'name': '',
                    'type': '',
                })

            scan_result['scan'][host] = PortScannerHostDict({'hostnames': hostnames})

            scan_result['scan'][host]['addresses'] = address_block
            scan_result['scan'][host]['vendor'] = vendor_block

            for dstatus in dhost.findall('status'):
                # status : up...
                scan_result['scan'][host]['status'] = {'state': dstatus.get('state'),
                                                       'reason': dstatus.get('reason')}
            for dstatus in dhost.findall('uptime'):
                # uptime : seconds, lastboot
                scan_result['scan'][host]['uptime'] = {'seconds': dstatus.get('seconds'),
                                                       'lastboot': dstatus.get('lastboot')}
            for dport in dhost.findall('ports/port'):
                # protocol
                proto = dport.get('protocol')
                # port number converted as integer
                port = int(dport.get('portid'))
                # state of the port
                state = dport.find('state').get('state')
                # reason
                reason = dport.find('state').get('reason')
                # name, product, version, extra info and conf if any
                name = product = version = extrainfo = conf = cpe = ''
                for dname in dport.findall('service'):
                    name = dname.get('name')
                    if dname.get('product'):
                        product = dname.get('product')
                    if dname.get('version'):
                        version = dname.get('version')
                    if dname.get('extrainfo'):
                        extrainfo = dname.get('extrainfo')
                    if dname.get('conf'):
                        conf = dname.get('conf')

                    for dcpe in dname.findall('cpe'):
                        cpe = dcpe.text
                # store everything
                if proto not in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host][proto] = {}

                scan_result['scan'][host][proto][port] = {'state': state,
                                                          'reason': reason,
                                                          'name': name,
                                                          'product': product,
                                                          'version': version,
                                                          'extrainfo': extrainfo,
                                                          'conf': conf,
                                                          'cpe': cpe}
                script_id = ''
                script_out = ''
                # get script output if any
                for dscript in dport.findall('script'):
                    script_id = dscript.get('id')
                    script_out = dscript.get('output')
                    if 'script' not in list(scan_result['scan'][host][proto][port].keys()):
                        scan_result['scan'][host][proto][port]['script'] = {}

                    scan_result['scan'][host][proto][port]['script'][script_id] = script_out

            # <hostscript>
            #  <script id="nbstat" output="NetBIOS name: GROSTRUC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: &lt;unknown&gt;&#xa;" />
            #  <script id="smb-os-discovery" output=" &#xa;  OS: Unix (Samba 3.6.3)&#xa;  Name: WORKGROUP\Unknown&#xa;  System time: 2013-06-23 15:37:40 UTC+2&#xa;" />
            #  <script id="smbv2-enabled" output="Server doesn&apos;t support SMBv2 protocol" />
            # </hostscript>
            for dhostscript in dhost.findall('hostscript'):
                for dname in dhostscript.findall('script'):
                    hsid = dname.get('id')
                    hsoutput = dname.get('output')

                    if 'hostscript' not in list(scan_result['scan'][host].keys()):
                        scan_result['scan'][host]['hostscript'] = []

                    scan_result['scan'][host]['hostscript'].append(
                        {
                            'id': hsid,
                            'output': hsoutput
                        }
                    )

            # <osmatch name="Juniper SA4000 SSL VPN gateway (IVE OS 7.0)" accuracy="98" line="36241">
            # <osclass type="firewall" vendor="Juniper" osfamily="IVE OS" osgen="7.X"
            # accuracy="98"><cpe>cpe:/h:juniper:sa4000</cpe><cpe>cpe:/o:juniper:ive_os:7</cpe></osclass>
            # </osmatch>
            # <osmatch name="Cymphonix EX550 firewall" accuracy="98" line="17929">
            # <osclass type="firewall" vendor="Cymphonix" osfamily="embedded"
            # accuracy="98"><cpe>cpe:/h:cymphonix:ex550</cpe></osclass>
            # </osmatch>
            for dos in dhost.findall('os'):
                osmatch = []
                portused = []
                for dportused in dos.findall('portused'):
                    # <portused state="open" proto="tcp" portid="443"/>
                    state = dportused.get('state')
                    proto = dportused.get('proto')
                    portid = dportused.get('portid')
                    portused.append({
                        'state': state,
                        'proto': proto,
                        'portid': portid,
                    })

                scan_result['scan'][host]['portused'] = portused

                for dosmatch in dos.findall('osmatch'):
                    # <osmatch name="Linux 3.7 - 3.15" accuracy="100" line="52790">
                    name = dosmatch.get('name')
                    accuracy = dosmatch.get('accuracy')
                    line = dosmatch.get('line')

                    osclass = []
                    for dosclass in dosmatch.findall('osclass'):
                        # <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="2.6.X" accuracy="98"/>
                        ostype = dosclass.get('type')
                        vendor = dosclass.get('vendor')
                        osfamily = dosclass.get('osfamily')
                        osgen = dosclass.get('osgen')
                        accuracy = dosclass.get('accuracy')

                        cpe = []
                        for dcpe in dosclass.findall('cpe'):
                            cpe.append(dcpe.text)

                        osclass.append({
                            'type': ostype,
                            'vendor': vendor,
                            'osfamily': osfamily,
                            'osgen': osgen,
                            'accuracy': accuracy,
                            'cpe': cpe,
                        })

                    osmatch.append({
                        'name': name,
                        'accuracy': accuracy,
                        'line': line,
                        'osclass': osclass
                    })
                else:
                    scan_result['scan'][host]['osmatch'] = osmatch

            for dport in dhost.findall('osfingerprint'):
                # <osfingerprint fingerprint="OS:SCAN(V=5.50%D=11/[...]S)&#xa;"/>
                fingerprint = dport.get('fingerprint')

                scan_result['scan'][host]['fingerprint'] = fingerprint

        self._scan_result = scan_result  # store for later use
        return scan_result

    def __gettime__(self, host):
        ''' 返回主机详情'''

        if sys.version_info[0] == 2:
            assert type(host) in (str, type(None)), 'Wrong type for [host], should be a string [was {0}]'.find(type(host))
        else:
            assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        return self._scan_result['scan'][host]

    def all_hosts(self):
        ''' 返回所有主机'''
        if 'scan' not in list(self._scan_result.keys()):
            return []
        list_host = list(self._scan_result['scan'].keys())
        list_host.sort()
        return list_host

    def command_line(self):
        ''' 返回 nmap 扫描使用的命令'''
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get  result!'
        assert 'scaninfo' in self._scan_result['nmap'], 'Do a scan befor trying to get result'
        return self._scan_result['nmap']['scaninfo']

    def scanstats(self):
        ''' 扫描状态'''
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'scanstats' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['scanstats']

    def has_host(self, host):
        """
        returns True if host has result, False otherwise
        """
        assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        assert 'scan' in self._scan_result, 'Do a scan before trying to get result !'

        if host in list(self._scan_result['scan'].keys()):
            return True

        return False

    def csv(self):
        ''' returns CSV output as text '''
        assert 'scan' in self._scan_result, 'Do a scan before trying to get result !'

        if sys.version_info < (3, 0):
            fd = io.BytesIO()
        else:
            fd = io.StringIO()

        csv_ouput = csv.writer(fd, delimiter=';')
        csv_header = [
            'host',
            'hostname',
            'hostname_type',
            'protocol',
            'port',
            'name',
            'state',
            'product',
            'extrainfo',
            'reason',
            'version',
            'conf',
            'cpe'
        ]

        csv_ouput.writerow(csv_header)

        for host in self.all_hosts():
            for proto in self[host].all_protocols():
                if proto not in ['tcp', 'udp']:
                    continue
                lport = list(self[host][proto].keys())
                lport.sort()
                for port in lport:
                    hostname = ''
                    for h in self[host]['hostnames']:
                        hostname = h['name']
                        hostname_type = h['type']
                        csv_row = [
                            host, hostname, hostname_type,
                            proto, port,
                            self[host][proto][port]['name'],
                            self[host][proto][port]['state'],
                            self[host][proto][port]['product'],
                            self[host][proto][port]['extrainfo'],
                            self[host][proto][port]['reason'],
                            self[host][proto][port]['version'],
                            self[host][proto][port]['conf'],
                            self[host][proto][port]['cpe']
                        ]
                        csv_ouput.writerow(csv_row)

        return fd.getvalue()


def __scan_progressive__(self, hosts, ports, arguments, callback, sudo):
    """
    Used by PortScannerAsync for callback
    """
    for host in self._nm.listscan(hosts):
        try:
            scan_data = self._nm.scan(host, ports, arguments, sudo)
        except PortScannerError:
            scan_data = None

        if callback is not None:
            callback(host, scan_data)
    return


class PortScannerAsync(object):
    ''' 使用 nmap 进行扫描'''

    def __init__(self):
        self._process = None
        self._nm = PortScanner()
        return

    def __del__(self):
        ''' 删除时清空'''
        if self._process is not None:
            try:
                if self._process.is_alive():
                    self._process.terminate()
            except AssertionError:
                pass
        self._process = None
        return

    def scan(self, hosts='127.0.0.1', ports=None, callback=None, sudo=False):
        ''' 扫描一台主机 '''
        if sys.version_info[0] == 2:
            assert type(hosts) in (str, type(None)), 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
            assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
            assert type(sudo) in (str, type(None)), 'Wrong type for [arguments], should be a string [was {0}]'.format(type(sudo))
        else:
            assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
            assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
            assert type(sudo) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(sudo))
        assert callable(callback) or callback is None, 'The [callback] {0} should be callable or None.'.format(str(callback))

        self._process = Process(
            target=__scan_progressive__,
            args=(self, hosts, ports, callback, sudo)
        )
        self._process.daemon = True
        self._process.start()
        return

    def stop(self):
        ''' 停止当前扫描'''
        if self._process is not None:
            self._process.terminate()
        return

    def wait(self, timeout=None):
        assert type(timeout) in (int, type(None)), 'Wrong type for [timeout], should be an int or None [was {0}]'.format(type(timeout))
        self._process.join(timeout)
        return

    def still_scanning(self):
        try:
            return self._process.is_alive()
        except:
            return False


class PortScannerYield(PortScannerAsync):
    def __init__(self):
        PortScannerAsync.__init__(self)
        return

    def scan(self, hosts='127.0.01', ports=None, arguments='-sV', sudo=False):
        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))

        for redirecting_output in ['-oX', '-oA']:
            assert redirecting_output not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'

        for host in self._nm.listscan(hosts):
            try:
                scan_data = self._nm.scan(host, ports, arguments, sudo)
            except PortScannerError:
                scan_data = None
            yield (host, scan_data)
        return

    def stop(self):
        pass

    def wait(self, timeout=None):
        pass

    def still_scanning(self):
        pass


class PortScannerHostDict(dict):
    def hostnames(self):
        return self['hostnames']

    @property
    def hostname(self):
        hostname = ''
        for h in self['hostnames']:
            if h['type'] == 'user':
                return h['name']
        else:
            if len(self['hostnames']) > 0 and 'name' in self['hostnames'][0]:
                return self['hostnames'][0]['name']
            else:
                return ''
        return hostname

    def state(self):
        """
        :returns: host state

        """
        return self['status']['state']

    def uptime(self):
        """
        :returns: host state

        """
        return self['uptime']

    def all_protocols(self):
        """
        :returns: a list of all scanned protocols

        """

        def _proto_filter(x):
            return x in ['ip', 'tcp', 'udp', 'sctp']

        lp = list(filter(_proto_filter, list(self.keys())))
        lp.sort()
        return lp

    def all_tcp(self):
        """
        :returns: list of tcp ports

        """
        if 'tcp' in list(self.keys()):
            ltcp = list(self['tcp'].keys())
            ltcp.sort()
            return ltcp
        return []

    def has_tcp(self, port):
        """
        :param port: (int) tcp port
        :returns: True if tcp port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('tcp' in list(self.keys())
                and port in list(self['tcp'].keys())):
            return True
        return False

    def tcp(self, port):
        """
        :param port: (int) tcp port
        :returns: info for tpc port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        return self['tcp'][port]

    def all_udp(self):
        """
        :returns: list of udp ports

        """
        if 'udp' in list(self.keys()):
            ludp = list(self['udp'].keys())
            ludp.sort()
            return ludp
        return []

    def has_udp(self, port):
        """
        :param port: (int) udp port
        :returns: True if udp port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('udp' in list(self.keys())
                and 'port' in list(self['udp'].keys())):
            return True
        return False

    def udp(self, port):
        """
        :param port: (int) udp port
        :returns: info for udp port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['udp'][port]

    def all_ip(self):
        """
        :returns: list of ip ports

        """
        if 'ip' in list(self.keys()):
            lip = list(self['ip'].keys())
            lip.sort()
            return lip
        return []

    def has_ip(self, port):
        """
        :param port: (int) ip port
        :returns: True if ip port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('ip' in list(self.keys())
                and port in list(self['ip'].keys())):
            return True
        return False

    def ip(self, port):
        """
        :param port: (int) ip port
        :returns: info for ip port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['ip'][port]

    def all_sctp(self):
        """
        :returns: list of sctp ports

        """
        if 'sctp' in list(self.keys()):
            lsctp = list(self['sctp'].keys())
            lsctp.sort()
            return lsctp
        return []

    def has_sctp(self, port):
        """
        :returns: True if sctp port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('sctp' in list(self.keys())
                and port in list(self['sctp'].keys())):
            return True
        return False

    def sctp(self, port):
        """
        :returns: info for sctp port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['sctp'][port]


class PortScannerError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'PortScannerError exception {0}'.format(self.value)


def __get_last_online_version():
    import http.client
    conn = http.client.HTTPConnection("xael.org")
    conn.request("GET", "/pages/python-nmap/python-nmap_CURRENT_VERSION.txt")
    online_version = bytes.decode(conn.getresponse().read()).strip()
    return online_version


def convert_nmap_output_to_encoding(value, code="ascii"):
    """
    Change encoding for scan_result object from unicode to whatever

    :param value: scan_result as dictionnary
    :param code: default = "ascii", encoding destination

    :returns: scan_result as dictionnary with new encoding
    """
    new_value = {}
    for k in value:
        if type(value[k]) in [dict, PortScannerHostDict]:
            new_value[k] = convert_nmap_output_to_encoding(value[k], code)
        else:
            if type(value[k]) is list:
                new_value[k] = [
                    convert_nmap_output_to_encoding(x, code) for x in value[k]
                ]
            else:
                new_value[k] = value[k].encode(code)
    return new_value
