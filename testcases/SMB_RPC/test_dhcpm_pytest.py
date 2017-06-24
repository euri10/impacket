###############################################################################
#  Tested so far: 
#
#  DhcpGetClientInfoV4
#  DhcpV4GetClientInfo
#
#  Not yet:
#
#
################################################################################

from collections import namedtuple

import pytest
from configparser import ConfigParser
import socket

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, dhcpm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
import os

current_dir = os.path.dirname(os.path.realpath(__file__))


def connect(tc, version):
    rpctransport = transport.DCERPCTransportFactory(tc.stringBinding)
    if len(tc.hashes) > 0:
        lmhash, nthash = tc.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''
    if hasattr(rpctransport, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpctransport.set_credentials(tc.username,tc.password, tc.domain, lmhash, nthash)
    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    if version == 1:
        dce.bind(dhcpm.MSRPC_UUID_DHCPSRV, transfer_syntax= tc.ts)
    else:
        dce.bind(dhcpm.MSRPC_UUID_DHCPSRV2, transfer_syntax= tc.ts)
    return dce, rpctransport


def test_DhcpGetClientInfoV4(transport_config):
    dce, rpctransport = connect(transport_config, 1)
    request = dhcpm.DhcpGetClientInfoV4()
    request['ServerIpAddress'] = NULL
    request['SearchInfo']['SearchType'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress
    request['SearchInfo']['SearchInfo']['tag'] = dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress
    ip = int(socket.inet_aton("172.16.123.10").encode('hex'), 16)
    request['SearchInfo']['SearchInfo']['ClientIpAddress'] = ip
    request.dump()
    resp = dce.request(request)
    resp.dump()


def test_hDhcpGetClientInfoV4(transport_config):
    dce, rpctransport = connect(transport_config, 1)
    ip = int(socket.inet_aton("172.16.123.10").encode('hex'), 16)
    resp = dhcpm.hDhcpGetClientInfoV4(dce, dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientIpAddress, ip)
    resp.dump()
    try:
        resp = dhcpm.hDhcpGetClientInfoV4(dce, dhcpm.DHCP_SEARCH_INFO_TYPE.DhcpClientName, 'PEPA\x00')
        resp.dump()
    except Exception as e:
        if str(e).find('0x4e2d') >= 0:
            pass


@pytest.fixture(scope="module", params=["TCPTransport", "SMBTransport", "TCPTransport64", "SMBTransport64"])
def transport_config(request):
    TransportConfig = namedtuple('TransportConfig',
                                 ['username', 'domain', 'serverName',
                                  'password',
                                  'machine', 'hashes', 'stringBinding', 'ts'],
                                 verbose=True)
    if request.param is "TCPTransport" or "TCPTransport64":
        confkey = "TCPTransport"
    elif request.param is "SMBTransport" or "SMBTransport64":
        confkey = "SMBTransport"
    configFile = ConfigParser()
    configFile.read(os.path.join(current_dir, 'dcetests.cfg'))
    username = configFile.get(confkey, 'username')
    domain = configFile.get(confkey, 'domain')
    serverName = configFile.get(confkey, 'servername')
    password = configFile.get(confkey, 'password')
    machine = configFile.get(confkey, 'machine')
    hashes = configFile.get(confkey, 'hashes')
    if request.param is "TCPTransport":
        sb = epm.hept_map(machine, dhcpm.MSRPC_UUID_DHCPSRV2, protocol='ncacn_ip_tcp')
        ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
    elif request.param is "TCPTransport64":
        sb = epm.hept_map(machine, dhcpm.MSRPC_UUID_DHCPSRV2, protocol='ncacn_ip_tcp')
        ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')
    elif request.param is "SMBTransport":
        sb = r'ncacn_np:%s[\PIPE\dhcpserver]' % machine
        ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
    elif request.param is "SMBTransport64":
        sb = r'ncacn_np:%s[\PIPE\dhcpserver]' % machine
        ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')
    stringBinding = sb
    ts = ts
    tc = TransportConfig(username=username, domain=domain,serverName=serverName,password=password,machine=machine,hashes=hashes, stringBinding=stringBinding, ts=ts)
    return tc


