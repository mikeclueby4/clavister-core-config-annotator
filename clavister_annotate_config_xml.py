
import os
import subprocess
import sys
import re
import io
import datetime
import base64
import binascii
import textwrap
import html
from dataclasses import dataclass
from typing import Callable,Dict,List,Union,Any,TextIO,BinaryIO,Optional,Tuple

CURRENT_CORE_VERSION = "12.00.21"

# sys.argv.append("c:/temp/tic-28025/config-cOS-Core-FW2-20190823.bak")
#sys.argv.append("c:/temp/tic-27950/anonymous_config-FW-03-iDirect-20190807-v8598.bak")
# sys.argv.append("C:/Users/Mike/AppData/Local/Temp/config-fw1-20190624-v186.bak")

# sys.argv.append(r"C:\Users\miol\AppData\Local\Temp\config-HFW00024-20190830.bak")
# sys.argv.append(r"C:\Users\Mike\AppData\Local\Temp\config-hhfirewall03-20190930-1450.bak-annotated.xml")
sys.argv.append(r"C:\Users\Mike\AppData\Local\Temp\anonymous_config-Device-20191202-v031.bak")

filename = sys.argv[1]

CommentGroups = []  # raw text lines, index=0 matches id=1, etc
RuleSets =  {}      # type: Dict[str, Optional[List[str]]]
                    # e.g. 'MyRuleSet' = [ "line", "line", ... ] or True
Names = {}          # type: Dict[str, List[str]]
                    # e.g. 'fooname' = [ "<iprule ...>", "<ip4address ...", ... ]


AllSettings = []    # raw text lines in order


#
# Notices
#

@dataclass
class Notice:
    message : str   # "wrong foo in bar"
    line : str      # actual line in configuration

AllNotices : List[Notice] = []


#
# Track Major Features
#


@dataclass
class Feature:
    lines : List[str]     # 0 or more examples of uses of this feature (config lines)
    count : int
    subclass : str     # "Routing", "Content Inspection", ...


AllFeatures : Dict[str, Feature]= {}    # will be dumped at end, e.g. "HA" = "<HighAvailability ...""

def addfeature(key, desc = None, subclass = None):
    if type(desc) is str:
        desc = re.sub(r"^\s+", "", desc)
    if not key in AllFeatures:
        AllFeatures[key] = Feature([], 1, subclass)
    else:
        AllFeatures[key].count += 1
    if desc and len(AllFeatures[key].lines)<3:
        AllFeatures[key].lines.append(desc)



#
# Open input file
#

filename = re.sub(r'-annotated\.xml$', '', filename)   # for notepad++ "Run" on already-annotated file
print(sys.argv[0] + ": processing " + filename)

f : TextIO

try:
    pass
    if re.search(r'\.bak', filename.lower()):
        with open(filename, "rb") as raw:
            rawdata = raw.read()
            assert rawdata[0:4]!="FPKG", ".bak file started with '" + str(rawdata[0:4]) + "', expected 'FPKG'"
            firstXmlLinePos = rawdata.find(b"<SecurityGateway")
            assert firstXmlLinePos>=0, "Could not find '<SecurityGateway' in file"
            lastXmlLinePos = rawdata.find(b"</SecurityGateway>")
            assert lastXmlLinePos>=0, "Could not find '</SecurityGateway>' in file"
            # f = io.StringIO(str(rawdata[firstXmlLinePos:(lastXmlLinePos+18)]), newline="\n")
            f = io.StringIO(newline=None)
            f.write(rawdata[firstXmlLinePos:(lastXmlLinePos+18)].decode("utf-8"))
            f.seek(0)
    else:
        f = open(filename)
except FileNotFoundError as e:
    sys.exit(sys.argv[0] + ": " + str(e))
except OSError as e:
    sys.exit(sys.argv[0] + ": " + str(e))



#
# Open outputfile and define out()
#

outfilename = filename + "-annotated.xml"
outfile = open(outfilename, "wt", encoding="utf-8")

print("Outputting to " + outfilename)


def out(*texts, stdout = False):
    for v in texts:
        if type(v) is str:
            outfile.write(v)
        else:
            outfile.write(repr(v))
    outfile.write("\n")
    if stdout:
        print(*texts,)

orig_out = out  # copy of original so out() can be locally redefined inside functions

def notice(message, line):
    header = "NOTICE: "
    indent = "        "

    outfile.write(header + re.sub(r"\n", "\n" + indent, message) + "\n")
    AllNotices.append( Notice(message, line) )




#
# UTILITY
#

def re_group(regex, string, groupnum, defaultvalue):
    ''' Return match.group(groupnum), or the defaultvalue if regex did not match '''
    m = re.search(regex, string)
    if not m:
        return defaultvalue
    return m.group(groupnum)

def shorten(text: str) -> str:
    ''' Shorten lines HARD, truncate params, remove params .. keep the line under 100 chars'''
    # shorten params:
    text = text.strip()
    text = re.sub(r'="([^"]{30,})"', lambda m: '="' + m.group(1)[0:20] + '..."', text)
    # shorten entire line
    if len(text)>100:
        text = re.sub(r' +[^=]+="[^"]*" *(/?>)', r" ... \1", text)
        safety=99
        while len(text)>100 and safety>0:
            text = re.sub(r' +[^=]+="[^"]*" *(/?>)', r"\1", text)
            safety-=1
    return text




dhdescs = { 1: "768-bit MODP", 2: "1024-bit MODP", 5: "1536-bit MODP", 14: "2048-bit MODP",
           15: "3072-bit MODP", 16: "4096-bit MODP", 17: "6144-bit MODP", 18: "8192-bit MODP",

           22: "1024-bit MODP with 160-bit Prime Order Subgroup",
           23: "2048-bit MODP with 224-bit Prime Order Subgroup",
           24: "2048-bit MODP with 256-bit Prime Order Subgroup",
           25: "192-bit Random ECP",
           26: "224-bit Random ECP",
           19: "256-bit Random ECP",
           20: "384-bit Random ECP",
           21: "521-bit Random ECP",
           }

def dhdesc(group, line):
    ''' Return description of given group number. Will also notice() about problems, using the supplied line as context '''
    if re.match(r" *[Nn]one *$", group):
        notice("Not using DH is not recommended. It MAY be acceptable for PFS, but we recommend at least group 5 and preferably group 14", line)
        return "None - don't use Diffie-Hellman key negotiation"

    try:
        igroup = int(group)
    except BaseException as e:
        return str(e)

    if not igroup or igroup not in dhdescs:
        return "UNKNOWN DIFFIE-HELLMAN GROUP " + group + " ?!"
    elif igroup>=1 and igroup<5:
        notice("Diffie-Hellman group " + group + " (" + dhdescs[igroup] + ") is no longer considered safe. Use minimum 1536-bit MODP (group 5). For general use we recommend 2048-bit (group 14).", line)
    elif igroup>=16 and igroup<=18:
        notice("Diffie-Hellman group " + group + " (" + dhdescs[igroup] + ") is TOO LARGE and will cause excessive CPU load. Use maximum 3072-bit MODP (group 15). For general use we recommend 2048-bit (group 14).", line)
    return dhdescs[igroup]


#
# Entropy estimation
#

import lzma
import random

def lzmalen(binarybytes:bytes) -> int:
    my_filters = [
        {"id":lzma.FILTER_LZMA1}
    ]
    lzc = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=my_filters)

    lzc.compress(b'01')  # ignore this length
    retlen = len(lzc.compress( binarybytes ))
    retlen += len(lzc.flush())

    return retlen

# expected lower+upper bounds of entropy for a given number of bits. computed as-needed and cached.
entropy_upperbounds: Dict[int,int] = {}   # e.g. 64 bits = 23 bytes,   128 bits = 39 bytes,  1024 bits = 218 bytes,  ....
entropy_lowerbounds: Dict[int,int] = {}   # e.g. 64 bits = 17 bytes,   128 bits = 32 bytes,  1024 bits = 203 bytes,  ....

def entropychecker(
    binarytext: Union[bytes,str],   # "0b11110010001010100100001001"
    line: str                       # context for notice()s
    ) -> Tuple[bool, int, int, int, int]:
    """
    Verify that the given binary string compresses down to an expected length

    Returns:
        result ≥= entropy_lowerbounds[numbits]*0.95,  # Bool
        numbits,                         # rounded up to byte-size
        result,                          # length of compression result
        entropy_lowerbounds[numbits],    # 10th percentile lowest seen for random data, i.e. "bad luck"
        entropy_upperbounds[numbits]     # highest seen for random data, i.e. "uncompressable"
    """
    if isinstance(binarytext, str):
        binarytext = bytes(binarytext, encoding="utf-8")

    assert(binarytext==b"0b0" or binarytext[0:3]==b"0b1")

    numbits = len(binarytext)-2
    numbits = int((numbits+7)/8)*8  # round up to nearest byte-size, mostly for cache hits in entropy_lowerbounds

    minimumlen = lzmalen(b'1')   # about 13 bytes

    if numbits not in entropy_lowerbounds:
        samples = [lzmalen( bytes( bin(random.getrandbits(numbits))[2:] , encoding="utf-8" )) - minimumlen   for i in range(0,100)]
        samples.sort()
        entropy_lowerbounds[numbits] = samples[10]
        entropy_upperbounds[numbits] = samples[-1]

    result = lzmalen(binarytext[2:])-minimumlen

    return result>=entropy_lowerbounds[numbits]*0.95, \
            numbits, \
            result, \
            entropy_lowerbounds[numbits], \
            entropy_upperbounds[numbits] \


#
# Preprocessing pass
#

lines = []

while True:
    line = f.readline()
    if not line:
        break

    indent = re_group(r'^(\s*)', line, 1, "")   # grab indent

    line = re.sub(r'\s+$', "", line)

    # CRLF in comments
    line = re.sub(r' Comments="[^"]*&#10;[^"]*"', lambda m: re.sub(r'&#1[03];', "  ", m.group(0)), line)

    lines.append(line)  # store line for next pass

    # Skip disabled lines
    if re.search(r'disabled="1".*/>', line):
        continue

    # Scrape CommentGroups
    m = re.search(r'<CommentGroup ', line)
    if m:
        CommentGroups.append(re.sub(r"^\s+", "", line))

  # Scrape all <....Settings> so we can repeat them at the end
    m = re.search(r"""(<([a-zA-Z0-9_.]+Settings|UpdateCenter))[ >]""", line)
    if m:
        AllSettings.append(line)

    # Scrape IPRuleSet
    m = re.search(r"""(<IPRuleSet .*Name="([^"]+)".*>)""", line)
    if m:
        rslines = []
        rsname = m.group(2)
        lines.append("        <!-- (will be displayed inline, below) -->")

        __line = line
        while not re.search(r"""</IPRuleSet>""", __line):
            rslines.append(__line)
            __line = f.readline()
            __line = re.sub(r'\s+$', "", __line)
            assert __line, "ERROR: missing </IPRuleSet>, hit end-of-file looking for it!"

        lines.append(__line)
        rslines.append(__line + "  <!-- " + rsname + " -->")

        RuleSets[rsname] = rslines


    # Insert IPRuleSet after GotoRule (first time used, only)
    m=re.search(r' RuleSet="([^"]+)', line)
    if m:
        rsname = m.group(1)
        if not rsname in RuleSets:
            notice("Could not find IPRuleSet '" + rsname + "'??!?", line)
        elif RuleSets[rsname]==None:
            lines.append(indent + "    <!-- IPRuleSet '" + rsname +"' already displayed above -->")
            lines.append("")
        else:
            for l in RuleSets[rsname]:   # type: ignore
                lines.append(indent + "    " + l)
            RuleSets[rsname]=None  # flag that it's already been displayed



    # Scrape names
    m = re.match(r"""\s+(<.* Name="([^"]+)".*>)""", line)
    if m:
        text = m.group(1)
        n = m.group(2)

        if re.match(r'<DefaultInterface ', text):
            pass    # we know this
        elif re.match(r'<IP4[HA]*Address ', text) and n in ["all-nets", "localhost"]:
            pass    # we know this
        elif re.match(r'<IP6[HA]*Address ', text) and n in ["all-nets6", "localhost6"]:
            pass    # we know this
        else:

            if not n in Names:
                Names[n] = []

            # Simplify stuff we don't need to see in recursive comments
            text = re.sub(r'="([^"]{60,999999})', lambda m: """="{}...[{} chars]""".format(m.group(1)[0:40], len(m.group(1))), text)
            text = re.sub(r' Comments="IP Address and Broadcast address of interface [-A-Za-z0-9_.]+"', '', text)
            text = re.sub(r' Comments="The network connected directly to the [^"]+"', '', text)
            text = re.sub(r' EthernetDevice[.0-9]*="[^"]+"', '', text)
            text = re.sub(r' HAPCI[A-Za-z]+="[^"]+"', '', text)
            text = re.sub(r' SNMPIndex="[^"]+"', '', text)
            text = re.sub(r' NOCHB="False"', '', text)
            text = re.sub(r' Name="[^"]+"', ' ', text)  # extra space because otherwise <IPRuleSet Name="foo"> becomes <IPRuleSet> which doesn't match r"<IPRuleset "
            text = re.sub(r'(<IP[46]Address )Address=', r'\1', text)
            text = re.sub(r' (Inherited|readOnly)="True"', '', text)

            if len(text)>420:
                text = text[0:400] + "...[" + str(len(text)-400) + " chars]"

            # Set the name and its text!
            Names[n].append( text )



#
# Names dumping func
#

def dumpnames(line, recurse=0):

    displayed={}

    # Grab current line indent
    m = re.match(r'^(\s*)', line)
    indent = m.group(1)

    # Grab XML entity name for display & logic
    m = re.match(r'^\s*<([-A-Za-z0-9_.]+)', line)
    if m:
        XMLentity = m.group(1)
    else:
        XMLentity = '???'


    # Find all Foo="Value" in the line
    param = {}
    for m in re.finditer(r'\s([a-zA-Z0-9_.]+)="([^"]+)"', line):
        paramname = m.group(1)
        param[paramname] = []
        for paramvalue in re.findall(r'[^,]+', m.group(2)):      # split on comma
            param[paramname].append(paramvalue.strip())

    for paramname,paramvalues in param.items():
      num=0
      for paramvalue in paramvalues:

        # parameters that do not contain resolvable names at all

        if re.match(r'^Service.*',XMLentity) and paramname in ["Protocol"]:
            continue

        if XMLentity=="PPPoETunnel" and paramname in ["ServiceName"]:
            continue

        if XMLentity=="UserAuthRule" and paramname in ["Agent", "AuthSource"]:
            continue

        if XMLentity=="User" and paramname=="Groups":
            continue

        if paramname in ["Name", "Description", "Comments", "Comment", "CommentGroup", "Description", "readOnly", "EMIName", "Ordering", "UserAuthGroups", "SNMPGetCommunity", "DebugDDesc", "TunnelProtocol"]:
            continue

        # stuff we're not interested in showing _WHEN_ _RECURSING_

        if recurse>0:
            if XMLentity=="InterfaceGroup" and paramname=="Members":
                continue
            if paramname in ["EthernetDevice", "EthernetDevice.0", "EthernetDevice.1"]:
                continue

        def dumpone(instance):
                if instance in displayed:
                    return
                displayed[instance] = True
                # Include commentgroup description
                cg = int(re_group(r' CommentGroup="([0-9]+)"', instance, 1, -1)) - 1
                if 0<=cg<len(CommentGroups):
                    desc = re_group(r' Description="([^"]+)"', CommentGroups[cg], 1, None)
                    if desc:
                        instance = re.sub(r' CommentGroup="([0-9]+)"', ' CommentGroup="' + desc + '"', instance)

                outline = indent + "        <!-- " + n + " = " + instance + " -->"
                out(outline)
                if recurse==0 or \
                   (recurse <=1 and re.match(r"<IP[46]HAAddress", instance)):
                    dumpnames(indent + "        " + instance, recurse+1)

        # Dump those we recognize as Names defined earlier
        n = re.sub(".*/", "", paramvalue)  # strip leading folder names
        if n in Names:

            num=num+1
            if num>5:
                pass
            elif num==5 and len(paramvalues)>5:
                out(indent + "        (skipping %u more)" % (len(paramvalues)-4))
                break

            # Map parameter name to what XML entity/ies we should be looking for
            find = r"<" + paramname  # default: if it's <xmlentity Foo="bar">, then look for a "<Foo" that had Name="bar"
            if XMLentity in ["WebProfile", "ALG_HTTP"] and paramname=="HTTPBanners":
                find = r"<HTTPALGBanners "
            elif paramname=="HTTPBanners":
                find = r"<HTTPAuthBanners "
            elif paramname in ["ForwardChain", "ReturnChain"]:
                find = r"<Pipe "
            elif paramname in ["HTTPSCertificate", "HostCertificate", "RootCertificate"]:
                find = r"<Certificate "
            elif paramname == "RadiusServers":
                find = r"<RadiusServer "
            elif paramname == "AC_RuleSet":
                find = r"<ApplicationRuleSet "
            elif paramname == "AV_Policy":
                find = r"<AntiVirusPolicy "
            elif paramname == "EC_Policy":
                find = r"<EmailControlProfile "
            elif paramname == "FC_Policy":
                find = r"<FileControlPolicy "
            elif paramname == "Web_Policy":
                find = r"<WebProfile "
            elif paramname == "DNS_Policy":
                find = r"<DNSProfile "
            elif paramname == "MACAddress":
                find = r"<EthernetAddress "
            elif paramname in ["IPAddress", "Network", "Broadcast", "PrivateIP", "Gateway", "SourceNetwork",
                               "DestinationNetwork", "OriginatorIP", "TerminatorIP", "ServerIP", "SourceIP",
                               "SLBAddresses",
                               "SATTranslateToIP", "NATSenderAddress",
                               "IPAddressPool", "Address.0", "Address.1",
                               "SourceNewIP", "DestNewIP",
                               "LocalEndpoint", "RemoteEndpoint", "MonitoredIP", "LocalNetwork", "RemoteNetwork", "OriginatorHAIP",
                               "IPPool",
                               "Addresses",
                               "InControlIP",
                               "DefaultGateway", "DNS1", "DNS2",  "NBNS1", "NBNS2", # DHCPServer
                               "Host",
                               "MulticastGroup", "MulticastSource",  # IGMPRule
                               "OuterIP", "InnerIP", "PrimaryDNS", "ClientRoutes", # SSLVPNInterface
                               "TargetDHCPServer", "TargetDHCPServer2",
                               "DHCPDNS1", "DHCPDNS2",  # dhcp-enabled interfaces
                               "DNSServer1", "DNSServer2", "DNSServer3",
                               "TimeSyncServer1", "TimeSyncServer2", "TimeSyncServer3"] or \
                 ( XMLentity in ["OSPFProcess"] and paramname=="RouterID" ) or \
                 ( XMLentity in ["DynamicRoutingRule"] and paramname=="DestinationNetworkIn" ) or \
                 ( XMLentity in ["BlacklistWhiteHost"] and paramname=="Address" ) or \
                 ( XMLentity in ["IP4Group","IP6Group"] and paramname=="Members" ):
                find = r"<(IP[46]Address|IP[46]HAAddress|IP[46]Group|FQDNAddress|FQDNGroup)"
            elif XMLentity == "ServiceGroup" and paramname=="Members":
                find = r"<Service"
            elif paramname in ["SourceInterface", "DestinationInterface","Interface","Interfaces","OuterInterface","ProxyARPInterfaces","IncomingInterfaceFilter","LoopTo", "IPsecInterface", "RelayInterface"] \
                 or ( XMLentity == "InterfaceGroup" and paramname=="Members"):
                find = r"<(InterfaceGroup|Ethernet|DefaultInterface|SSLVPNInterface|LoopbackInterface|IPsecTunnel|L2TPv?[23]?Server|VLAN|LinkAggregation|L2TPv?[23]?Client|PPPoETunnel) "
            elif paramname in ["EthernetDevice.0", "EthernetDevice.1", "SyncIface"]:
                find = r"<EthernetDevice "
            elif paramname=="Key":
                find = r"<PSK "
            elif paramname in ["OutgoingRoutingTable", "ForwardRoutingTable", "ReturnRoutingTable"]:
                find = r"<RoutingTable "
            elif XMLentity=="DynamicRoutingRuleAddRoute" and paramname in ["Destination"]:
                find = r"<RoutingTable "
            elif XMLentity=="DynamicRoutingRuleExportOSPF" and paramname in ["ExportToProcess"]:
                find = r"<OSPFProcess "
            elif XMLentity=="FQDNGroup" and paramname=="Members":
                find = r"<FQDNAddress "
            elif XMLentity=="LinkAggregation" and paramname=="Members":
                find = r"<Ethernet "
            elif paramname=="BaseInterface":
                find = r"<(Ethernet|LinkAggregation) "
            elif paramname=="SourceGeoFilter":
                find = r"<GeolocationFilter "
            elif paramname=="ConfigUser":  # <SecurityGateway
                find = r"<User "
            elif paramname=="SSHKeys": # <User
                find = r"<SSHClientKey "
            elif paramname=="IKEConfigModePool":  # <IPsecTunnel
                find = r"<ConfigModePool "
            elif paramname in ["RootCertificates", "GatewayCertificate"]: # <IPsecTunnel
                find = r"<Certificate "
            elif XMLentity=="GotoRule" and paramname=="RuleSet":
                find = r"<IPRuleSet "
            elif paramname=="LocalUserDB":
                find = r"<LocalUserDatabase "
            elif paramname=="RemoteID":
                find = r"<IDList "
            elif paramname=="EthernetInterface":    # PPPoETunnel
                find = r"<(Ethernet|VLAN) "

            # Find according to type ("find" regex)
            found=0
            for instance in Names[n]:

                if re.match(find, instance):
                    dumpone(instance)
                    found=found+1

            if found==1:
                pass
            elif found>2:
                out("found too many (tell miol) ^^^") # crap
            else:
                out("FUZZY MATCH ATTEMPT (tell miol):")  # miol needs to work
                for instance in Names[n]:
                    dumpone(instance)


#
# Certificate and private key dumping
#

try:
    import cryptography    # "pip install cryptography"   (windows: run in elevated command prompt)
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend as cryptography_hazmat_backends_default_backend
    from cryptography.hazmat.primitives import serialization as cryptography_hazmat_primitives_serialization

except ImportError:
    cryptography = None

warned_about_cryptography=False

def has_cryptography():
    if cryptography:
        return True
    global warned_about_cryptography
    if not warned_about_cryptography:
        notice("The PyCA 'cryptography' module is not installed. If you do 'pip install cryptography' in an elevated command prompt, I can show you the cert contents!", None)
        warned_about_cryptography=True
    return False


def unpem(pemder):
    if type(pemder) is str:
        pemder=bytes(pemder, "ASCII")
    pemder = re.sub(b"---+[ A-Za-z0-9]+---+", b"", pemder)
    pemder = re.sub(b"^[ \t\r\n]+", b"", pemder)
    pemder = re.sub(b"[ \t\r\n]+$", b"", pemder)
    try:
        decoded = base64.standard_b64decode(pemder)
        return decoded
    except binascii.Error:   # python3 only?
        pass
    except binascii.Incomplete: # python3 only?
        pass
    except TypeError:    # python2 only?
        pass

    # that wasn't base64! assume it's DER and don't touch it
    return pemder


# Certificate
def DumpCertificate(out : Callable,
                    pemder : str,
                    line : str
                    ) -> Tuple[Any, bool]:    # cert, anonymized
    '''
    Parse and dump info about given certificate through the given out()

    out: function to output the dump, must take parameters like the global out()"
    pemder: PEM or DER format data
    line: context for notice() calls
    '''
    if pemder==None:
        return None, False

    der = unpem(pemder)
    if b"\x02" not in der:
        out("Base64 decoding again because contents are %s (%i bytes)" %(repr(der[0:80]), len(der)))
        # unpack again because clavister privkey format in config are funny that way
        der = unpem(der)

    if not has_cryptography():
        return None, False

    try:
        cert = x509.load_der_x509_certificate(der, cryptography_hazmat_backends_default_backend())
    except ValueError as e:
        out(str(e), " - data was ", repr(der[0:80]), " (%u bytes)" % len(der))
        return None, False

    try:
        pubkey = cert.public_key()
    except ValueError as e:
        out("Error parsing certificate: tried to get public key and got: ", str(e))
        return None, False

    # custom repr() implementation incl error handling

    cryptography.hazmat.backends.openssl.x509._SignedCertificateTimestamp.__repr__ = lambda obj: "<_SignedCertificateTimestamp()>"

    def myrepr(obj, attr):   # repr() and remove some junk we don't need to see 99% of the time
        try:
            txt = repr(getattr(obj, attr))
            if re.match(r"^<KeyUsage", txt):
                txt = re.sub(r"[a-zA-Z0-9_]+=(False|None),*\s*", "", txt)
            txt = re.sub(r"^<[A-Za-z0-9_]+\((.*)\)>\s*$", r"\1", txt)  # always remove outermost <Foo(...)>
            txt = re.sub(r"^<[A-Za-z0-9_]+\((.*)\)>\s*$", r"\1", txt)  # and again
            txt = re.sub(r"<UniformResourceIdentifier\(value=('http[^']*')\)>", r"\1", txt)
            txt = re.sub(r"\(value=('[^']*')\)", r" \1", txt)    # (value='foo') -> ('foo')
            txt = re.sub(r"<ObjectIdentifier\((oid=[^)]+)\)>", r"(\1)", txt)  # so this won't hit if obj is an oid
        except ValueError as e:
            return "<" + attr + ": Error: " + str(e) + ">"
        return txt

    anonymized = ("CN=Anonymous" in myrepr(cert, "subject")) and (pubkey.key_size==511)
    if anonymized:
        out("This certificate has been replaced with an anonymized dummy certificate. Not dumping contents.")
        return cert, True

    out("Subject: " + myrepr(cert, "subject"))

    out("Public key size: %u bits" % pubkey.key_size)

    if pubkey.key_size>3100:
        notice("""Key size %u TOO LARGE. You never need more than 3072 bits. This will cause major CPU hits if computed often.
It MAY be okay if external parties cannot trigger it. But anything open to many users is a potential hazard.""" % pubkey.key_size, line)
    elif pubkey.key_size>2100:
        notice("Key size %u is probably larger than needed. You typically never need more than 2048 bits unless national security is involved." % pubkey.key_size, line)
    elif pubkey.key_size<800:
        notice("Key size %u is TRIVIALLY CRACKABLE. Use at least 1536. Preferably 2048." % pubkey.key_size, line)
    elif pubkey.key_size<1500:
        notice("Key size %u is considered unsafe. Use at least 1536. Preferably 2048." % pubkey.key_size, line)


    assert(cert.serial_number==0 or bin(cert.serial_number)[0:3]=="0b1")   # we're assuming "0b" and no leading zeroes for the .count()s below
    num1 = bin(cert.serial_number)[2:].count("1")
    num0 = bin(cert.serial_number)[2:].count("0")
    out("Serial: %u (0x%x - %u ones, %u zeroes%s)" %
            (cert.serial_number, cert.serial_number, num0, num1,
            " - good!" if num0+num1>=63 and num0>=28 and num1>=28 else ""\
    )    )
    if num0+num1 < 63:
        notice("""Serial number 0x%x is shorter than 63 bits, so cannot possibly contain 63+ bits of entropy.
This may open the certificate up to hash collision attacks!""" % cert.serial_number, line)
    else:
        # This is not a test of GOOD entropy. For all we know, someone is setting 90% of the serial to 01010101... all the time. But it'll catch known-BAD behavior.
        if num0<24 or num1<24:  # in any decent-entropy PRNG
            notice("""Serial number 0x%x contains %u ones and %u zeroes. Expected 24+ of both.
This smells like bad entropy and may open the certificate up to hash collision attacks!""" \
                % (cert.serial_number, num1, num0), line)

    out("Validity (UTC): ", cert.not_valid_before.strftime("%Y-%m-%d %H:%M"), " -- ", cert.not_valid_after.strftime("%Y-%m-%d %H:%M") )
    if cert.not_valid_before > datetime.datetime.utcnow():
        notice("Certificate not valid yet! Earliest: " + cert.not_valid_before.strftime("%Y-%m-%d %H:%M"), line)
    if datetime.datetime.utcnow() > cert.not_valid_after:
        notice("Certificate no longer valid! Latest: " + cert.not_valid_after.strftime("%Y-%m-%d %H:%M"), line)
    elif datetime.datetime.utcnow() + datetime.timedelta(days=14) > cert.not_valid_after:
        notice("Certificate expires soon: " + cert.not_valid_after.strftime("%Y-%m-%d %H:%M"), line)

    out("Issuer: ", myrepr(cert, "issuer"))
    # not needed, part of signature algorithm out("Signature hash algorithm: ", str(cert.signature_hash_algorithm))
    out("Signature algorithm: ", myrepr(cert, "signature_algorithm_oid"))

    from cryptography.x509.oid import _OID_NAMES

    for ext in cert.extensions:
        if ext.oid in _OID_NAMES:
            out(_OID_NAMES[ext.oid],": oid=",ext.oid.dotted_string.strip(), ext.critical and " (CRITICAL) " or " () ", myrepr(ext, "value"))
        else:
            out("Extension: ", myrepr(ext, "oid"), ext.critical and " (CRITICAL) " or " () ", myrepr(ext, "value"))
            if ext.critical:
                notice("Contained CRITICAL extension " + ext.oid.dotted_string.strip() + " which I don't recognize so in THEORY this is an invalid certificate. Maybe. Except x509 and standards so who knows.", line)

    return cert, False

# Private key
def DumpPrivateKey(out, pemder, line, anonymized=False):
    if pemder==None:
        return

    der = unpem(pemder)
    if b"\x02" not in der:
        out("Base64 decoding again because contents are %s (%i bytes)" %(repr(der[0:80]), len(der)))
        # unpack again because clavister privkey format in config are funny that way
        der = unpem(der)

    if not has_cryptography():
        return
    try:
        key = cryptography_hazmat_primitives_serialization.load_der_private_key(der, None, cryptography_hazmat_backends_default_backend())
    except TypeError as e:  # it was password protected!
        notice("Private key was password protected, which will never work! - %s" % (e), line)
        return
    except ValueError as e:   # broken DER
        notice("%s - data was %s (%i bytes)" % (e, repr(der[0:80]), len(der)), line)
        return
    except cryptography.exceptions.UnsupportedAlgorithm as e:
        notice("%s - data was %s (%i bytes)" % (e, repr(der[0:80]), len(der)), line)
        return

    if anonymized:
        out("Anonymized private key")       # no point showing anything
        return

    from cryptography.hazmat.primitives.asymmetric import dsa,rsa,ec
    if isinstance(key, rsa.RSAPrivateKey):
        out("RSA private key, %u bits" % (key.key_size))

    elif isinstance(key, dsa.DSAPrivateKey):
        out("DSA private key, %u bits" % (key.key_size))

    elif isinstance(key, ec.EllipticCurvePrivateKey):
        curvename = key.curve.name
        aka = {   # from https://tools.ietf.org/html/rfc8422#appendix-A
            "sect163k1" : "NIST K-163",
            "sect163r2" : "NIST B-163",
            "sect233k1" : "NIST K-233",
            "sect233r1" : "NIST B-233",
            "sect283k1" : "NIST K-283",
            "sect283r1" : "NIST B-283",
            "sect409k1" : "NIST K-409",
            "sect409r1" : "NIST B-409",
            "sect571k1" : "NIST K-571",
            "sect571r1" : "NIST B-571",
            "secp192r1" : "NIST P-192",
            "secp224r1" : "NIST P-224",
            "secp256r1" : "NIST P-256",
            "secp384r1" : "NIST P-384",
            "secp521r1" : "NIST P-521"
            }
        curvename += ' aka "' + aka[curvename] + '"'   if curvename in aka else ""

        out("EC private key, %u bits, curve: %s" % (key.key_size, curvename))

        if re.match(r"sec", curvename):
            out(key.curve.name + " was designed by NIST in FIPS 186-4. Please read https://safecurves.cr.yp.to/")

    else:
        notice("I don't know what type of key this is?! Tried RSA,DSA,EC.  : %s" % (repr(key)), line)
        return








#
# Output pass
#

out("<!-- from " + filename + "  - " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " -->")

currentCommentGroup=0
currentCommentGroupIndent=0

for line in lines:
    line = re.sub(r'[ \t\r\n]+$', "", line)

    # Comment out disabled lines
    if re.search(r' disabled="1"[ />]', line):
        line = re.sub(r"""^(\s+)""", r"""\1<!-- disabled! --> """, line)
        out(line)
        out("")
        continue

    # Grab current line indent
    indent = re_group(r'^(\s*)', line, 1, "")


    # Strip out things that never need to be shown
    line = re.sub(r' SourceAddressTranslation="None"', "", line)


    # Prepend CommentGroup lines when we enter a new group
    if not re.match(r"\s*</", line):
        cg = int(re_group(r' CommentGroup="([0-9]+)"', line, 1, 0))
        if cg!=currentCommentGroup:
            if cg==0 and len(indent) > currentCommentGroupIndent:
                pass    # assume it's a sub-item .. jeez this is ugly
            else:
                if currentCommentGroup>0:
                    out((" " * currentCommentGroupIndent) + "</CommentGroup>")
                    out("")

                currentCommentGroup=cg
                currentCommentGroupIndent = len(indent)
                if cg==0:
                    currentCommentGroupIndent = 0
                elif cg <= len(CommentGroups):
                    out("")
                    out(indent + re.sub(r"/>", ">", CommentGroups[cg-1]))
                else:
                    out(indent + "<CommentGroup id={0}>   <!-- Unknown id {0}, we only have {1} -->".format(cg, len(CommentGroups)) )

                out("")

    if currentCommentGroup>0:
        indent = indent + "    "
        out("    " + line)
    else:
        out(line)


    #
    # WARNINGS
    #

    def expectmatch(ifmatch, expectmatch):
        if re.search(ifmatch, line) and not re.search(expectmatch, line):
            notice(f"Expected [ {ifmatch} ] to have [ {expectmatch} ] - it did not!", line)

    # MulticastPolicy
    if re.match(r'\s*<MulticastPolicy ',line):
        if not re.search(r' RequireIGMP="False"',line):
            notice("""This has RequireIGMP="True"(default) which usually is unnecessary and may cause glitches with units that don't speak IGMP like they should. Is it really necessary, or should we set  RequireIGMP="False" ?   (IGMP is normally only useful for high-bandwidth streams.)""", line)

        destif = re_group(r'DestinationInterface="([^"]+)"', line, 1, "???")
        if not destif in ["core","any"]:
            notice(f"""Expected DestinationInterface to be "core" or "any" but it was "{destif}" - will this ever trigger? (It might if we're not dealing with actual multicast IPs but ... eh)""", line)

    # DynamicRoutingRule DestinationNetworkIn="all-nets" or "0.0.0.0/0"  = no import filtering = somewhat dangerous
    if re.match(r'\s*<DynamicRoutingRule .*DestinationNetworkIn=', line):
        filter = re_group(r'DestinationNetworkIn="([^"]+)"', line, 1, "???")
        if "all-nets" in filter or "0.0.0.0/0" in filter:
            notice(f"""No filtering (all-nets or 0.0.0.0/0) on imported networks - that's usually mildly dangerous; an attacker can re-route sensitive addresses!""", line)
            if "HA" in AllFeatures and len([line for line in lines if "<OSPFProcess " in line]) >= 2:
                notice(f"""... and HA is enabled and there's 2+ OSPF processes, so you may be in danger of triggering COP-22321""", line)



    # Not latest firmware
    if re.match(r'\s*<SecurityGateway ', line):
        m = re.search(r' SchemaVersion="(([0-9]+)\.([0-9]+)\.([0-9]+))', line)
        if not m:
            notice("""Couldn't find a SchemaVersion="nn.nn.nn..." ?""", line)
        elif m.group(1) != CURRENT_CORE_VERSION:
            notice("SchemaVersion was %s - latest is %s. (This may be due to InControl Global schema version and unavoidable because of older firewalls in the tree.)" % (m.group(1), CURRENT_CORE_VERSION), line)

        m = re.search(r' ConfigDate="([^"]+)', line)
        if not m:
            notice("""Couldn't find a ConfigDate="yyyy-mm-dd hh:mm:ss" ?""", line)
        else:
            delta = ( datetime.datetime.utcnow() - datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S") ).total_seconds()
            if delta < -3600*12:   # accept up to 12 timezones ahead
                notice("Config date is in the future?", line)
            elif delta > 3600*24*7*2:
                notice("Config date is %u weeks ago. (Is there a newer one?)" % (delta/3600/24/7), line)

    # Screen saver active = bad for CPU
    if re.match(r'\s*<MiscSettings.* ScrSave="', line):
        notice("Non-blank screensaver in use - causes small but unnecessary CPU hickups every screen update", line)

    # FwdFast/StatelessPolicy = bad for CPU
    if re.search(r' Action="FwdFast"', line):
        notice("FwdFast rule in use - if this forwards thousands of PPS it will cause high CPU load", line)
    if re.search(r'<StatelessPolicy ', line):
        notice("StatelessPolicy in use - if this forwards thousands of PPS it will cause high CPU load", line)

    # world-to-one SAT
    if re.search(r' DestAddressTranslation="SAT".*DestAddressAction="SingleIP".*DestinationNetwork="(all-nets|all-nets6|0.0.0.0/0)"', line):
        notice("Rewriting Dest=0.0.0.0/0 to one IP. This might work for HTTP. Will likely _NOT_ work for HTTPS, due to certificates. Double check what we are trying to do.", line)

    # Nutty DH groups in IPsec
    dhs = re_group(r' DHGroup="([^"]+)"', line, 1, "")
    for dh in re.findall(r'[^,]+', dhs):
        out(indent + "        <!-- DHGroup " + dh + " = " + dhdesc(dh, line) + " -->") # will also warn if bad
    dhs = re_group(r' PFSDHGroup="([^"]+)"', line, 1, "")
    for dh in re.findall(r'[^,]+', dhs):
        out(indent + "        <!-- PFSDHGroup " + dh + " = " + dhdesc(dh, line) + " -->") # will also warn if bad

    # Nutty monitoring
    n = re_group(r' MaxLoss="([0-9]+)"', line, 1, None)
    if n and int(n)<2:
        notice("That's a very low MaxLoss - risks happening too often!", line)
    elif n and int(n)>30:
        notice("That's a very high MaxLoss - it'll take a very long time to trigger!", line)



    # Services that people like to edit and will confuse us
    if re.match(r"^\s*<ServiceTCPUDP ", line):
        expectmatch(r' Name="http" ', r' DestinationPorts="80" ')
        expectmatch(r' Name="https" ', r' DestinationPorts="443" ')
        expectmatch(r' Name="http-all" ', r' DestinationPorts="80, 443" ')
        expectmatch(r' Name="ike" ', r' DestinationPorts="500" ')




    #
    # Certificate? SSH keys?
    #
    def outputter(*texts):
        out(indent + "        <!-- ", *texts, " -->")
    def unesc(foo):
        if foo:
            return html.unescape(foo)
        return foo

    if re.match(r'\s*<Certificate ', line):
        out(indent + "    <!-- CertificateData ==== -->")
        cert,anonymized = DumpCertificate(outputter, unesc(re_group(r' CertificateData="([^"]+)"', line, 1, None)) , shorten(line))
        out(indent + "    <!-- PrivateKey ==== -->")
        DumpPrivateKey(outputter, unesc(re_group(r' PrivateKey="([^"]+)"', line, 1, None)) , shorten(line), anonymized=anonymized)

    if re.match(r'\s*<SSHHostKey ', line):
        out(indent + "    <!-- Key ==== -->")
        DumpPrivateKey(outputter, unesc(re_group(r' Key="([^"]+)"', line, 1, None)) , shorten(line))


    #
    # Make note of major features
    #

    if re.match(r'\s*<HighAvailability ', line):
        addfeature("HA", line)
    if re.match(r'\s*<IPsecTunnel ', line):
        addfeature("IPsec Tunnels")
    if re.match(r'\s*<L2TPv?[23]?Server ', line):
        addfeature("L2TP Server", shorten(line))
    if re.match(r'\s*<L2TPv?[23]?Client ', line):
        addfeature("L2TP Client", shorten(line))
    if re.match(r'\s*<PipeRule ', line):
        addfeature("Pipe Rules")
    if re.match(r'\s*<IP(Rule|Policy) ', line):
        addfeature("Rules")
    if re.match(r'\s*<SLBPolicy ', line):
        addfeature("SLB", shorten(line))
    if re.match(r'\s*<LinkMonitor ', line):
        addfeature("LinkMonitor", shorten(line))

    subclass = "Routing"
    if re.match(r'\s*<RoutingRule ', line):   # only trigger only RoutingRule, we don't care if there's unused routing tables for the "feature in use" display
        addfeature("Policy-Based Routing (PBR)", shorten(line), subclass)
    if re.match(r'\s*<Route .* RouteMonitor="True" ', line):
        addfeature("Route monitoring", shorten(line), subclass)
    if re.match(r'\s*<RouteBalancingInstance ', line):
        addfeature("Route Balancing", shorten(line), subclass)
    if re.match(r'\s*<LoopbackInterface ', line):
        addfeature("Loopback Interface", shorten(line), subclass)
    if re.match(r'\s*<LinkAggregation ', line):
        addfeature("Link Aggregation", shorten(line), subclass)
    if re.search(r' AutoSwitchRoute="True"', line):
        addfeature("Transparent Mode", shorten(line), subclass)
    if re.match(r'\s*<OSPFProcess ', line):
        addfeature("OSPF", shorten(line), subclass)

    subclass = "Content Inspection"
    if re.match(r'\s*<EmailControlProfile ', line):
        addfeature("EmailControlProfile", shorten(line), subclass)
    if re.match(r'\s*<WebProfile ', line):
        addfeature("WebProfile", shorten(line), subclass)
    if re.match(r'\s*<AntiVirusPolicy ', line):
        addfeature("AntiVirusPolicy", shorten(line), subclass)
    if re.match(r'\s*<FileControlPolicy ', line):
        addfeature("FileControlPolicy", shorten(line), subclass)

    #
    # Output names we see in the line (recursively, 1 level)
    #

    if re.match(r"\s*<!--", line):
        pass

    else:

        dumpnames(line)

        out("")



#
# FINAL LOGIC
#

for k,v in RuleSets.items():
    if v!=None:
        txt = "Info: Unused IPRuleSet: " + v[0]  # type: ignore
        print(txt)
        out("<!-- " + txt + "-->")


#
# RE-DUMP ALL SETTINGS FOUND
#

out("")
out("<!-- ALL SETTINGS BELOW - USUALLY ONLY ONES CHANGED FROM DEFAULTS -->")
for txt in AllSettings:
    out("")
    out("   " + txt)
out("")


#
# OUTPUT FEATURES IN USE
#

byclass: Dict[str,Dict[str,Feature]]= {}

for key,feat in AllFeatures.items():
    c = feat.subclass
    if not c in byclass:
        byclass[c] = {}
    byclass[c][key] = feat

for subclass,features in byclass.items():
    out("")
    out("<!-- ", subclass or "MAJOR FEATURES", " -->")

    for key,feat in features.items():
        out("")
        prefix = "    %-16s " % key
        indent = " " * len(prefix)
        if len(feat.lines)<1:
            out("{}{}".format(prefix, feat.count))
        else:
            for desc in feat.lines:
                out(prefix + desc)
                prefix = indent
            if len(feat.lines) < feat.count:
                out("{}({} more)".format(indent, feat.count-len(feat.lines)))

out("")



#
# AT EOF: RE-DUMP NOTICES FOUND
#

if len(AllNotices)>0:
    out("", stdout=True)
    out("<!-- COPY OF NOTICES FOUND ABOVE: -->", stdout=True)

    NoticesForLine: Dict[str,List[str]] = {}   # line = list of messages
    NoticeCounts: Dict[str,int] = {}
    header = "        NOTICE: "
    indent = "                "
    for noti in AllNotices:
        # Count repetitions of the _message_, ignore 6+ of it
        NoticeCounts[noti.message] = NoticeCounts.get(noti.message, 0) + 1
        if NoticeCounts[noti.message] > 5:
            continue
        # Group all messages for the same line
        if noti.line not in NoticesForLine:
            NoticesForLine[noti.line] = []
        NoticesForLine[noti.line].append(noti.message)

    # Output!
    for line,messages in NoticesForLine.items():
        out("", stdout = True)
        if noti.line:
            out("  " + line, stdout = True)
        for message in messages:
            out(header + re.sub(r"\n", "\n"+indent, message), stdout = True)

    # Warn about repeated messages
    out("", stdout = True)
    for message,count in NoticeCounts.items():
        if count>5:
            out("This notice occured {} more times:   (see inline for all)".format(count-5))
            out("    " + message)




out("<!-- EOF -->")

print("")
print("Done. Written to " + outfilename)
outfile.close()


tried = []
for pf in [os.environ.get('ProgramW6432'), os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)')]:
    if pf:
        exe = pf + "\\Notepad++\\notepad++.exe"
        tried.append(exe)
        if os.path.isfile(exe):
            print('Executing "{}" "{}"'.format(exe, outfilename) )
            subprocess.call( [exe, outfilename] )
            break
else:
        print("Can't find notepad++ to launch. Tried " + ", ".join(tried))
