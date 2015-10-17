import os
import re
import struct

import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.scan as scan
import volatility.utils as utils
import volatility.win32.modules as modules
import volatility.win32.tasks as tasks


# Add some structures
_thing_types = {

    # Not sure what it is, so let's call it a "thing".
    '_THING': [ 0x86, {
        'header': [ 0x00, ['unsigned long']],  # NDsh
        'ver': [ 0x04, ['unsigned long']],  # 0x00000001 (version?)
        'eth': [ 0x08, ['_ETHERNET']]  # Always an ethernet packet?
    }],

    # Ethernet Header
    '_ETHERNET': [ 0xE, {
        'mac_dst': [ 0x00, ['array', 6, ['unsigned char']]],
        'mac_src': [ 0x06, ['array', 6, ['unsigned char']]],
        'eth_type': [0x0C, ['unsigned be short']]
    }],

    # IPv4 Header
    '_IPv4': [ 0x20, {
        'version': [ 0x00, ['BitField', dict(start_bit=4, end_bit=8, native_type='unsigned long')]],
        'ihl': [ 0x00, ['BitField', dict(start_bit=0, end_bit=4, native_type='unsigned long')]],
        'length': [ 0x02, ['unsigned be short']],
        'ttl': [ 0x08, ['unsigned char']],
        'proto': [ 0x09, ['unsigned char']],
        'src_ip': [0x0C, ['array', 4, ['unsigned char']]],
        'dst_ip': [0x10, ['array', 4, ['unsigned char']]]
    }],

    # IPv6 Header
    '_IPv6': [ 0x28, {
        'version': [ 0x00, ['BitField', dict(start_bit=4, end_bit=8, native_type='unsigned long')]],
        'pld_len': [ 0x04, ['unsigned be short']],
        'nxt_hdr': [ 0x06, ['unsigned char']],
        'src_ip': [0x08, ['array', 16, ['unsigned char']]],
        'dst_ip': [0x18, ['array', 16, ['unsigned char']]],
    }],

    # UDP Header
    '_UDP': [ 0x08, {
        'src_port': [ 0x00, ['unsigned be short']],
        'dst_port': [ 0x02, ['unsigned be short']],
        'length'  : [ 0x04, ['unsigned be short']],
        'checksum': [ 0x06, ['unsigned be short']]
    }],

    # TCP Header
    '_TCP': [ 0x14, {
        'src_port': [ 0x00, ['unsigned be short']],
        'dst_port': [ 0x02, ['unsigned be short']],
        'seq_num' : [ 0x04, ['unsigned long']],
        'ack_num' : [ 0x08, ['unsigned long']],
        'data_off': [ 0x0C, ['BitField', dict(start_bit=4, end_bit=8, native_type='unsigned char')]],
        'reserved': [ 0x0C, ['BitField', dict(start_bit=1, end_bit=4, native_type='unsigned char')]],
        'ns'      : [ 0x0C, ['BitField', dict(start_bit=0, end_bit=1, native_type='unsigned char')]],
        'cwr'     : [ 0x0D, ['BitField', dict(start_bit=7, end_bit=8, native_type='unsigned char')]],
        'ece'     : [ 0x0D, ['BitField', dict(start_bit=6, end_bit=7, native_type='unsigned char')]],
        'urg'     : [ 0x0D, ['BitField', dict(start_bit=5, end_bit=6, native_type='unsigned char')]],
        'ack'     : [ 0x0D, ['BitField', dict(start_bit=4, end_bit=5, native_type='unsigned char')]],
        'psh'     : [ 0x0D, ['BitField', dict(start_bit=3, end_bit=4, native_type='unsigned char')]],
        'rst'     : [ 0x0D, ['BitField', dict(start_bit=2, end_bit=3, native_type='unsigned char')]],
        'syn'     : [ 0x0D, ['BitField', dict(start_bit=1, end_bit=2, native_type='unsigned char')]],
        'fin'     : [ 0x0D, ['BitField', dict(start_bit=0, end_bit=1, native_type='unsigned char')]],
        'win_size': [ 0x0E, ['unsigned be short']],
        'checksum': [ 0x10, ['unsigned be short']],
        'urg_ptr' : [ 0x12, ['unsigned be short']]
    }]
}

class _THING(obj.CType):

    # Supported EtherTypes
    _valid_ethtype = [
        0x0800, # IPv4
        0x86dd, # IPv6
    ]

    def is_valid(self):
        """Check this is a Thing we can parse"""

        return (self.ver == 1 and self.eth.eth_type in self._valid_ethtype)

    def __str__(self):
        """Get string representation of Thing"""

        return '<Thing (header={:X}, ver={}, eth={:X})>'.format(
            self.header, self.ver, self.eth.eth_type)
    

class _ETHERNET(obj.CType):

    @staticmethod
    def make_mac(mac):
        """Get MAC address as formatted string"""

        return ':'.join(['{:02X}'.format(x) for x in mac])    


class _IPv4(obj.CType):
    
    def is_tcp(self):
        """Check if this IPv4 packet contains a TCP payload"""

        return self.proto == 6

    def is_udp(self):
        """Check if this IPv4 packet contains a TCP payload"""

        return self.proto == 17

    def get_proto(self):
        """Get the prototype value"""

        return self.proto

    def payload_offset(self):
        """Get the packet offset to the payload"""

        return self.v() + (self.ihl * 4)

    @staticmethod
    def make_ip(ip):
        """Get string representation of IPv4 address"""

        return '.'.join(['{}'.format(x) for x in ip])

class _IPv6(obj.CType):
    
    def is_tcp(self):
        """Check if this IPv6 packet contains a TCP payload"""

        return self.nxt_hdr == 6

    def is_udp(self):
        """Check if this IPv6 packet contains a UDP payload"""

        return self.nxt_hdr == 17

    def get_proto(self):
        """Get the prototype value"""

        return self.nxt_hdr

    def payload_offset(self):
        """Get the packet offset to the payload"""

        return self.v() + 40

    @staticmethod
    def make_ip(ip):
        """Get string representation of IPv6 address"""

        # TODO: There's gotta be a cleaner way, right?
        r = ''
        for i in xrange(0, ip.size(), 2):
            a = '{:x}'.format(ip[i])
            b = '{:x}'.format(ip[i+1])
            if a == '0' and b == '0':
                r += '0'
            elif a == '0':
                r += b
            else:
                r += a + '{:02x}'.format(ip[i+1])
            r += ':'
        r = r[0:-1]  # Strip the trailing ':'
        return r


class _UDP(obj.CType):
    
    def get_flags(self):
        """Get filler in place of TCP flags"""

        return '---'


class _TCP(obj.CType):

    def get_flags(self):
        """Get string representation of TCP flags"""

        flags = []
        if self.ns == 1: flags.append('NS')
        if self.cwr == 1: flags.append('CWR')
        if self.ece == 1: flags.append('ECE')
        if self.urg == 1: flags.append('URG')
        if self.ack == 1: flags.append('ACK')
        if self.psh == 1: flags.append('PSH')
        if self.rst == 1: flags.append('RST')
        if self.syn == 1: flags.append('SYN')
        if self.fin == 1: flags.append('FIN')
        return ','.join(flags)


class ThingVTypes(obj.ProfileModification):
    """Add the new vtypes"""

    def check(self, profile):
        m = profile.metadata
        return m.get('os', None) == 'windows'

    def modification(self, profile):
        profile.vtypes.update(_thing_types)

        
class ThingObjectClasses(obj.ProfileModification):
    """Add the new class definitions"""

    def modification(self, profile):
        profile.object_classes.update({
            '_THING': _THING,
            '_ETHERNET': _ETHERNET,
            '_IPv4': _IPv4,
            '_IPv6': _IPv6,
            '_UDP': _UDP,
            '_TCP': _TCP
        })

class PcapWriter:
    """Writes the packets found to a PCAP file"""

    # PCAP File Header
    pcap_header = struct.pack(
        '>I2H4I',
        0xa1b2c3d4,  # magic_number (Big-Endian)
        0x2,         # version_major
        0x4,         # version_minor
        0x0,         # thiszone
        0x0,         # sigfigs
        0x800,       # snaplen (2048)
        0x1          # network (1=eth)
    )

    def __init__(self, target):

        self.target = target
        self.packets = []

    @staticmethod
    def make_rec_header(p_len):
        """Create a record header for each packet record"""

        pcap_rec_header = struct.pack(
            '>4I',
            0x0,   # ts_sec
            0x0,   # ts_usec
            p_len, # incl_len
            p_len  # orig_len
        )
        return pcap_rec_header

    def write(self):
        """Write the packets to the PCAP file"""

        byte_count = len(self.pcap_header)
        with open(self.target, 'wb') as f:
            f.write(self.pcap_header)
            for packet in self.packets:
                data = self.make_rec_header(len(packet)) + packet
                f.write(data)
                byte_count += len(data)
        return byte_count
    

class NDshScanner(scan.BaseScanner):
    """Scanner for the 'NDsh' marker"""

    # Is this a pool tag?
    # It's on the list, but seems very generic:
    # http://blogs.technet.com/b/yongrhee/archive/2009/06/24/pool-tag-list.aspx
    # Seems to belong to ndis.sys (Network Driver Interface Specification)
    _MARKER = "NDsh"

    def __init__(self):
        needles = [ self._MARKER ]
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles}) ]
        scan.BaseScanner.__init__(self)

    def scan(self, address_space, offset=0):
        for address in scan.BaseScanner.scan(self, address_space, offset=offset):
            yield address

class MacScanner(scan.BaseScanner):
    """Scanner for a MAC address followed by IPv4/IPv6 EtherType"""

    def __init__(self, mac):
        needles = [ mac + '\x08\x00', mac + '\x86\xdd']
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles}) ]
        scan.BaseScanner.__init__(self)

    def scan(self, address_space, offset=0):
        for address in scan.BaseScanner.scan(self, address_space, offset=offset):
            yield address - 14  # So that we can force it into a _THING object


class NDISPktScan(common.AbstractWindowsCommand):
    """Extract the Things from memory"""

    #ip_proto = {
    #    0x00 : "IPv6 Hop-by-Hop Option",
    #    0x01 : "ICMP",
    #    0x02 : "IGMP",
    #    0x06 : "TCP",
    #    0x11 : "UDP",
    #    0x3A : "ICMP for IPv6",
    #}

    #def lookup_ip_proto(self, proto):
    #    proto = int(proto)
    #    if proto in self.ip_proto.keys():
    #        return '{:#x} ({})'.format(proto, self.ip_proto[proto])
    #    else:
    #        return '{:#x} (Unknown)'.format(proto)

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        # Config options
        config.add_option('PCAP', short_option = 'p', default = None,
                          help = 'Save to PCAP file', action = 'store')

        config.add_option('DSTS', short_option = 'D', default = None,
                          help = 'Save the destination IPs to a text file')
        
        config.add_option('SLACK', short_option = 's', default = False,
                          help = 'Look for slack only', action = 'store_true')

        config.add_option('MAC', short_option = 'm', default = None,
                          help = 'Source MAC address to find')

    @staticmethod    
    def trans_netbios(nb_name):
        """
        Translates a NetBIOS name into a sensible one
        https://support.microsoft.com/en-gb/kb/194203
        """

        lookup = {
            'EB': 'A',
            'EC': 'B',
            'ED': 'C',
            'EE': 'D',
            'EF': 'E',
            'EG': 'F',
            'EH': 'G',
            'EI': 'H',
            'EJ': 'I',
            'EK': 'J',
            'EL': 'K',
            'EM': 'L',
            'EN': 'M',
            'EO': 'N',
            'EP': 'O',
            'FA': 'P',
            'FB': 'Q',
            'FC': 'R',
            'FD': 'S',
            'FE': 'T',
            'FF': 'U',
            'FG': 'V',
            'FH': 'W',
            'FI': 'X',
            'FJ': 'Y',
            'FK': 'Z',
            'DA': '0',
            'DB': '1',
            'DC': '2',
            'DD': '3',
            'DE': '4',
            'DF': '5',
            'DG': '6',
            'DH': '7',
            'DI': '8',
            'DJ': '9',
            'CA': ' ',
            'CB': '!',
            'CC': '"',
            'CD': '#',
            'CE': '$',
            'CF': '%',
            'CG': '&',
            'CH': "'",
            'CI': '(',
            'CJ': ')',
            'CK': '*',
            'CL': '+',
            'CM': ',',
            'CN': '-',
            'CO': '.',
            'DN': '=',
            'DK': ':',
            'DL': ';',
            'EA': '@',
            'FO': '^',
            'FP': '_',
            'HL': '{',
            'HN': '}',
            'HO': '~',
            'AA': ''  # \x00
        }
        nb_chars = [nb_name[i:i+2] for i in range(0, len(nb_name), 2)]
        return ''.join([lookup[x] for x in nb_chars])

    @staticmethod
    def is_netbios_name(rx, maybe):
        """Check if string is valid NetBIOS name"""

        return rx.match(maybe)
    
    @staticmethod
    def validate_mac(mac):
        """Validate the MAC address option"""
        
        mac = mac.replace(':', '')
        if not re.match('^[a-fA-F0-9]{12}$', mac):
            return None
        
        return mac.decode('hex')
    
    @staticmethod
    def tidy_slack(slack):
        """Make the slack data human-friendly"""
        
        r = re.sub('[^A-Za-z0-9_-]', '.', slack)
        return r.strip('.')

    def calculate(self):

        if self._config.SLACK and (self._config.DSTS or self._config.PCAP):
            debug.error('SLACK can\'t be used with PCAP or DSTS')
        
        # Make sure the MAC address is valid
        if self._config.MAC:
            hex_mac = self.validate_mac(self._config.MAC)
            if not hex_mac:
                debug.error('Invalid MAC address')
    
        # Ensure PCAP file won't overwrite an existing file
        if self._config.PCAP and os.path.exists(self._config.PCAP):
            debug.error('\'{}\' already exists.  Cowardly refusing to overwrite it...'.format(
                self._config.PCAP))

        # Ensure DSTS file won't overwrite an existing file
        if self._config.DSTS and os.path.exists(self._config.DSTS):
            debug.error('\'{}\' already exists.  Cowardly refusing to overwrite it...'.format(
                self._config.DSTS))

        if self._config.SLACK:
            # Compiled RegEx = (tiny) increase in efficiency
            # NetBIOS code chars
            self.rx_nbchars = re.compile('^([ACDEFH][A-P])+$')

        # Get the start of kernel space
        addr_space = utils.load_as(self._config)
        kdbg = tasks.get_kdbg(addr_space)
        start = kdbg.MmSystemRangeStart.dereference_as("Pointer")

        # 64-bit to 48-bit adjustment
        # TODO: Is there a more Volatility-esque way of doing this?
        if start > 0xffff000000000000:
            start = start & 0x0000ffffffffffff

        # Modules so we can map addresses to owners
        mods = dict((addr_space.address_mask(mod.DllBase), mod)
                    for mod in modules.lsmod(addr_space))
        mod_addrs = sorted(mods.keys())
        
        if self._config.MAC:
            scanner = MacScanner(hex_mac)
        else:        
            scanner = NDshScanner()

        sessions = []
        hits = []
        for proc in tasks.pslist(addr_space):
            sid = proc.SessionId
            if sid == None or sid in sessions:
                continue

            session_space = proc.get_process_address_space()
            if session_space == None:
                continue

            sessions.append(sid)
            for address in scanner.scan(session_space, offset=start):
                
                if address in hits:
                    continue
            
                hits.append(address)
                module = tasks.find_module(mods, mod_addrs, addr_space.address_mask(address))
                thing = obj.Object('_THING', vm=session_space, offset=address)
                if thing.is_valid() or self._config.MAC:
                    raw = session_space.zread(address + 8, 2048)
                    # Parse ethernet's payload
                    if thing.eth.eth_type == 0x0800: # IPv4:
                        eth_payload = obj.Object('_IPv4', vm=session_space,
                            offset = thing.eth.v() + 0x0E)
                        end = 14 + eth_payload.length
                        if self._config.SLACK:
                            yield address, raw[end:]
                            continue
                        raw = raw[:end]
                    elif thing.eth.eth_type == 0x86dd: # IPv6
                        eth_payload = obj.Object('_IPv6', vm=session_space,
                            offset = thing.eth.v() + 0x0E)
                        end = 14 + 40 + eth_payload.pld_len
                        if self._config.SLACK:
                            yield address, raw[end:]
                            continue
                        raw = raw[:end]
                    else:
                        print "Error(1): Unsupported Ethernet Payload: {}".format(
                            thing.eth.eth_type)
                        continue
                    # Parse ethernet's payload's payload
                    if eth_payload.is_tcp():
                        payload = obj.Object('_TCP', vm=session_space,
                            offset=eth_payload.payload_offset())
                    elif eth_payload.is_udp():
                        payload = obj.Object('_UDP', vm=session_space,
                            offset=eth_payload.payload_offset())
                    else:
                        yield raw, thing, eth_payload, None
                        continue
                    yield raw, thing, eth_payload, payload
                #else:
                #    print '{:#x} Unknown Thing'.format(thing.v())

    def render_text(self, outfd, data):

        if self._config.SLACK:
        
            # Output the table header
            self.table_header(outfd, [
                    ("Offset (V)", "[addrpad]"),
                    ("Slack Data", "")
                ])
            
            count = 0
            for offset, slack in data:
                better_slack = self.tidy_slack(slack)
                if self.is_netbios_name(self.rx_nbchars, better_slack):
                    better_slack = '{} ({})'.format(
                        better_slack,
                        self.trans_netbios(better_slack).rstrip(' ')
                    )
                if len(better_slack) > 1:
                    count += 1
                    self.table_row(outfd,
                        offset,
                        better_slack
                    )
            outfd.write('Found {:,} "sensible" slack items.\n'.format(count))
        
        else:
        
            # Output the table header
            self.table_header(outfd, [
                    ("Offset (V)", "[addrpad]"),
                    ("Source MAC", "17"),
                    ("Destination MAC", "17"),
                    ("Prot", "3"),
                    ("Source IP", "39"),
                    ("Destination IP", "39"),
                    ("SPort", "5"),
                    ("DPort", "5"),
                    ("Flags", "")
                ])

            # If save to PCAP, create the writer object
            if self._config.PCAP:
                pcap_writer = PcapWriter(self._config.PCAP)

            dsts = set()  # Store the destination IPs
            count = 0
            for raw, t, e, p in data:
                count += 1
                
                if self._config.PCAP:  # Only if save to PCAP
                    pcap_writer.packets.append(raw)

                dst = e.make_ip(e.dst_ip)
                dsts.add(dst)

                self.table_row(outfd,
                    t.v(),
                    t.eth.make_mac(t.eth.mac_src),
                    t.eth.make_mac(t.eth.mac_dst),
                    '{:#04x}'.format(e.get_proto()),
                    e.make_ip(e.src_ip),
                    dst,
                    p.src_port if p else 'Proto',
                    p.dst_port if p else 'NotKn',
                    p.get_flags() if p else 'own'
                )

            outfd.write('Found {:,} Things.\n'.format(count))

            # Suggest trying the --mac option
            if count < 1 and not self._config.MAC:

                outfd.write('Zero-Hits-Tip: Consider the --mac option.\n')

            # Only write the files if we found something
            if count > 0:

                # If save to PCAP, write and report
                if self._config.PCAP:
                    written = pcap_writer.write()
                    outfd.write('Written {:,} records ({:,} bytes) to \'{}\'.\n'.format(
                        len(pcap_writer.packets), written, pcap_writer.target))

                # If save to DSTS, write and report
                if self._config.DSTS:
                    with open(self._config.DSTS, 'w') as dsts_file:
                        for dst in dsts:
                            dsts_file.write(dst + '\n')
                    outfd.write('Written {:,} destination IPs to \'{}\'.\n'.format(
                        len(dsts), self._config.DSTS))
