"""
This module provides a Splunk Modular input that operates a DNS proxy. The DNS
proxy logs requests and replies in Splunk.
"""
import sys
import os
import binascii

path_to_mod_input_lib = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modular_input.zip')
sys.path.insert(0, path_to_mod_input_lib)

from modular_input import IntegerField, DomainNameField, Field, ModularInput

import splunk.appserver.mrsparkle.lib.util as util
lib_dir = os.path.join(util.get_apps_dir(), 'dns_proxy', 'bin', 'dns_proxy_app')

if not lib_dir in sys.path:
    sys.path.append(lib_dir)

from event_writer import StashNewWriter

from dnslib.proxy import ProxyResolver, PassthroughDNSHandler
from dnslib.server import DNSLogger, DNSServer
from dnslib import DNSRecord, DNSError, QTYPE, RCODE, RR

class SplunkDNSLogger:
    def __init__(self, index, source, sourcetype):
        self.writer = StashNewWriter(index=index, source_name=source, sourcetype=sourcetype,
                                file_extension=".stash_output")

    def log_prefix(self,handler):
        return ""

    def log_pass(self,*args):
        pass

    def log_recv(self,handler,data):
        self.writer.write_event({
            'type': 'received',
            'client_address': handler.client_address[0],
            'client_port': handler.client_address[1],
            'protocol': handler.protocol,
            'length': len(data),
            'data': binascii.hexlify(data)
        })

    def log_send(self,handler,data):
        self.writer.write_event({
            'type': 'sent',
            'client_address': handler.client_address[0],
            'client_port': handler.client_address[1],
            'protocol': handler.protocol,
            'length': len(data),
            'data': binascii.hexlify(data)
        })

    def log_request(self,handler,request):
        self.writer.write_event({
            'type': 'request',
            'client_address': handler.client_address[0],
            'client_port': handler.client_address[1],
            'protocol': handler.protocol,
            'query_name': request.q.qname,
            'response_type': QTYPE[request.q.qtype]
        })
        self.log_data(request)

    def log_reply(self,handler,reply):
        if reply.header.rcode == RCODE.NOERROR:
            self.writer.write_event({
                'type': 'reply',
                'client_address': handler.client_address[0],
                'client_port': handler.client_address[1],
                'protocol': handler.protocol,
                'query_name': reply.q.qname,
                'response_type': QTYPE[reply.q.qtype],
                'response_records': ",".join([QTYPE[a.rtype] for a in reply.rr])
            })
        else:
            self.writer.write_event({
                'type': 'reply',
                'client_address': handler.client_address[0],
                'client_port': handler.client_address[1],
                'protocol': handler.protocol,
                'query_name': reply.q.qname,
                'response_type': QTYPE[reply.q.qtype],
                'response_code': reply.header.rcode
            })
        self.log_data(reply)

    def log_truncated(self,handler,reply):
        self.writer.write_event({
            'type': 'truncated_reply',
            'client_address': handler.client_address[0],
            'client_port': handler.client_address[1],
            'protocol': handler.protocol,
            'query_name': reply.q.qname,
            'response_type': QTYPE[reply.q.qtype],
            'response_records': ",".join([QTYPE[a.rtype] for a in reply.rr])
        })

    def log_error(self,handler,e):
        self.writer.write_event({
            'type': 'invalid_request',
            'client_address': handler.client_address[0],
            'client_port': handler.client_address[1],
            'protocol': handler.protocol,
            'error': str(e)
        })

    def log_data(self,dnsobj):
        pass
        #print("\n", dnsobj.toZone("    "), "\n", sep="")

class DNSProxyInput(ModularInput):
    """
    The main class that executes the modular input.
    """
    def __init__(self):
        scheme_args = {
            'title': "DNS Proxy Server",
            'description': "Provides a DNS server for the purposes of monitoring DNS requests.",
            'use_external_validation': "true",
            'streaming_mode': "xml",
            'use_single_instance': "true"
        }

        args = [
            Field("upstream_dns", "Upstream DNS Server", "The DNS server to pass the DNS queries to (e.g. 208.67.222.222)", empty_allowed=False),
            DomainNameField("address", "Address", "The address to serve the DNS proxy on; leave blank to operate the DNS server on all interfaces", empty_allowed=True),
            IntegerField("port", "Port", "The port to server the proxy server on", empty_allowed=False)
        ]

        ModularInput.__init__(self, scheme_args, args, logger_name='dns_proxy_modular_input')

        self.udp_server = None
        self.tcp_server = None

    def run(self, stanza, cleaned_params, input_config):
        # Stop if the DNS server already exists
        if self.udp_server is not None:
            return

        # Get the arguments
        port = cleaned_params.get("port", 53)
        address = cleaned_params.get("address", "")
        upstream_dns = cleaned_params.get("upstream_dns", None)
        index = cleaned_params.get("index", "default")
        sourcetype = cleaned_params.get("sourcetype", "dns_proxy")
        source = cleaned_params.get("source", "dns_proxy")

        self.logger.info("Starting the DNS server, port=%i, upstream_dns=%s", port, upstream_dns)

        # Prep the DNS server and port
        upstream_dns_server, _, upstream_dns_port = upstream_dns.partition(':')
        upstream_dns_port = int(upstream_dns_port or 53)

        resolver = ProxyResolver(upstream_dns_server, upstream_dns_port, 5)
        handler = PassthroughDNSHandler
        dns_logger = SplunkDNSLogger(index, source, sourcetype)

        # Start the UDP server
        self.udp_server = DNSServer(resolver,
                                    port=port,
                                    address=address,
                                    logger=dns_logger,
                                    handler=handler)

        self.udp_server.start_thread()

        # Start the TCP server
        self.tcp_server = DNSServer(resolver,
                               port=port,
                               address=address,
                               tcp=True,
                               logger=dns_logger,
                               handler=handler)
        self.tcp_server.start_thread()

if __name__ == '__main__':
    DNSProxyInput.instantiate_and_execute()
