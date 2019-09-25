
import os
import subprocess
import sys
import re
import io
import datetime
import base64
import binascii
import textwrap

#sys.argv.append("c:/temp/tic-28025/config-cOS-Core-FW2-20190815.bak")
#sys.argv.append("c:/temp/tic-27950/anonymous_config-FW-03-iDirect-20190807-v8598.bak")
# sys.argv.append("C:/Users/Mike/AppData/Local/Temp/config-fw1-20190624-v186.bak")

sys.argv.append(r"C:\Users\miol\AppData\Local\Temp\config-HFW00024-20190830.bak")

filename = sys.argv[1]

CommentGroups = []  # raw text lines, index=0 matches id=1, etc
RuleSets = {}       # e.g. 'MyRuleSet' = [ "line", "line", ... ]
Names = {}          # Will contain e.g. 'fooname' = [ "<iprule ...>", "<ip4address ...", ... ]
AllFeatures = {}    # will be dumped at end, "HA" = "<HighAvailability ...""
AllSettings = []    # raw text lines in order
AllNotices = []     # raw text lines in order



#
# Open input file
#

filename = re.sub(r'-annotated\.xml$', '', filename)   # for notepad++ "Run" on already-annotated file
print(sys.argv[0] + ": processing " + filename)

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


#
# Open outputfile and define out()
#

outfilename = filename + "-annotated.xml"
outfile = open(outfilename, "wt", encoding="utf-8")


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

def notice(text, line):
    header = "NOTICE: "
    indent = "        "

    outfile.write(header + re.sub(r"\n", "\n" + indent, text) + "\n")
    AllNotices.append( { "line": line, "text": text } )

print("Outputting to " + outfilename)
out("<!-- from " + filename + "  - " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " -->")

#
# UTILITY
#

def re_group(regex, string, groupnum, defaultvalue):
    ''' Return match.group(groupnum), or the defaultvalue if regex did not match '''
    m = re.search(regex, string)
    if not m:
        return defaultvalue
    return m.group(groupnum)

def shorten(text):
    return re.sub(r'="([^"]{30,})"', lambda m: '="' + m.group(1)[0:20] + '..."', text)

def addfeature(key, desc = None, subclass = None):
    if type(desc) is str:
        desc = re.sub(r"^\s+", "", desc)
    if not key in AllFeatures:
        AllFeatures[key] = {'lines': [], 'count': 1}
    else:
        AllFeatures[key]['count'] += 1
    if desc and len(AllFeatures[key]['lines'])<3:
        AllFeatures[key]['lines'].append(desc)

    AllFeatures[key]['subclass'] = subclass



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
    if igroup>=1 and igroup<5:
        notice("Diffie-Hellman group " + group + " is no longer considered safe. Use minimum 1536-bit MODP (group 5). For general use we recommend 2048-bit (group 14).", line)
    elif igroup>=16 and igroup<=18:
        notice("Diffie-Hellman group " + group + " is TOO LARGE and will cause excessive CPU load. Use maximum 3072-bit MODP (group 15). For general use we recommend 2048-bit (group 14).", line)
    return dhdescs[igroup]





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
    m = re.search(r"""(<IPRuleSet .*Names="([^"]+)".*>)""", line)
    if m:
        rslines = []
        rsname = m.group(2)
        lines.append("        <!-- (will be displayed inline, below) -->")

        while not re.search(r"""</IPRuleSet>""", line):
            rslines.append(line)
            line = f.readline()
            line = re.sub(r'\s+$', "", line)
            assert line, "ERROR: missing </IPRuleSet>, hit end-of-file looking for it!"

        lines.append(line)
        rslines.append(line + "  <!-- " + rsname + " -->")

        RuleSets[rsname] = rslines


    # Insert IPRuleSet after GotoRule (first time used, only)
    m=re.search(r' RuleSets="([^"]+)', line)
    if m:
        rsname = m.group(1)
        if not rsname in RuleSets:
            notice("Could not find IPRuleSet '" + rsname + "'??!?", line)
        elif RuleSets[rsname]==True:
            lines.append(indent + "    <!-- IPRuleSet '" + rsname +"' already displayed above -->")
            lines.append("")
        else:
            rslines = RuleSets[rsname]
            for l in rslines:
                lines.append(indent + "    " + l)
            RuleSets[rsname]=True  # flag that it's already been displayed



    # Scrape names
    m = re.match(r"""\s+(<.* Name="([^"]+)" .*>)""", line)
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
            text = re.sub(r' Name="[^"]+"', '', text)
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

        if re.match(r'^Service.*',XMLentity) and paramname in ["Protocol"]:
            continue

        if XMLentity=="UserAuthRule" and paramname in ["Agent", "AuthSource"]:
            continue

        if paramname in ["Name", "Description", "Comments", "Comment", "CommentGroup", "Description", "readOnly", "EMIName", "Ordering"]:
            continue

        if recurse>0:  # stuff we're not interested in showing _WHEN_ _RECURSING_
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
            if XMLentity=="WebProfile" and paramname=="HTTPBanners":
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
                               "DefaultGateway", "DNS1", "DNS2", "Host",
                               "TargetDHCPServer", "TargetDHCPServer2",
                               "DNSServer1", "DNSServer2", "DNSServer3",
                               "TimeSyncServer1", "TimeSyncServer2", "TimeSyncServer3"] or \
                 ( XMLentity in ["IP4Group","IP6Group"] and paramname=="Members" ):
                find = r"<(IP[46]Address|IP[46]HAAddress|IP[46]Group|FQDNAddress|FQDNGroup)"
            elif XMLentity == "ServiceGroup" and paramname=="Members":
                find = r"<Service"
            elif paramname in ["SourceInterface", "DestinationInterface","Interface","Interfaces","OuterInterface","ProxyARPInterfaces","IncomingInterfaceFilter","LoopTo"] or \
                 ( XMLentity == "InterfaceGroup" and paramname=="Members"):
                find = r"<(InterfaceGroup|Ethernet|DefaultInterface|SSLVPNInterface|LoopbackInterface|IPsecTunnel|L2TPServer|VLAN|LinkAggregation) "
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
def DumpCertificate(prefix, pemder):
    if pemder==None:
        return
    out = lambda *texts: orig_out(prefix, stdout=False, *texts, )

    der = unpem(pemder)
    if b"\x02" not in der:
        out("Base64 decoding again because contents are %s (%i bytes)" %(repr(der[0:80]), len(der)))
        # unpack again because clavister privkey format in config are funny that way
        der = unpem(der)

    if not has_cryptography():
        return
    try:
        cert = x509.load_der_x509_certificate(der, cryptography_hazmat_backends_default_backend())
    except ValueError as e:
        out(str(e), " - data was ", repr(der[0:80]), " (%u bytes)" % len(der))
        return

    cryptography.hazmat.backends.openssl.x509._SignedCertificateTimestamp.__repr__ = lambda obj: "<_SignedCertificateTimestamp()>"

    def myrepr(obj):   # repr() and remove some junk we don't need to see 99% of the time
        txt = repr(obj)
        if re.match(r"^<KeyUsage", txt):
            txt = re.sub(r"[a-zA-Z0-9_]+=(False|None),*\s*", "", txt)
        txt = re.sub(r"^<[A-Za-z0-9_]+\((.*)\)>\s*$", r"\1", txt)  # always remove outermost <Foo(...)>
        txt = re.sub(r"^<[A-Za-z0-9_]+\((.*)\)>\s*$", r"\1", txt)  # and again
        txt = re.sub(r"<UniformResourceIdentifier\(value=('http[^']*')\)>", r"\1", txt)
        txt = re.sub(r"\(value=('[^']*')\)", r" \1", txt)    # (value='foo') -> ('foo')
        txt = re.sub(r"<ObjectIdentifier\((oid=[^)]+)\)>", r"(\1)", txt)  # so this won't hit if obj is an oid

        return txt


    line = "Subject: " + myrepr(cert.subject)    # save for notices
    out(line)

    pubkey = cert.public_key()
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


    assert(bin(cert.serial_number)[0:3]=="0b1")
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
        if num0<26 or num1<26:  # in any decent-entropy PRNG
            notice("""Serial number 0x%x contains %u ones and %u zeroes. Expected 26+ of both.
This smells like bad entropy and may open the certificate up to hash collision attacks!""" \
                   % (cert.serial_number, num1, num0), line)

    out("Validity (UTC): ", cert.not_valid_before.strftime("%Y-%m-%d %H:%M"), " -- ", cert.not_valid_after.strftime("%Y-%m-%d %H:%M") )
    if cert.not_valid_before > datetime.datetime.utcnow():
        notice("Certificate not valid yet! Earliest: " + cert.not_valid_before.strftime("%Y-%m-%d %H:%M"), line)
    if datetime.datetime.utcnow() > cert.not_valid_after:
        notice("Certificate no longer valid! Latest: " + cert.not_valid_after.strftime("%Y-%m-%d %H:%M"), line)

    out("Issuer: ", myrepr(cert.issuer))
    # not needed, part of signature algorithm out("Signature hash algorithm: ", str(cert.signature_hash_algorithm))
    out("Signature algorithm: ", myrepr(cert.signature_algorithm_oid))

    from cryptography.x509.oid import _OID_NAMES

    for ext in cert.extensions:
        if ext.oid in _OID_NAMES:
            out(_OID_NAMES[ext.oid],": oid=",ext.oid.dotted_string.strip(), ext.critical and " (CRITICAL) " or " () ", myrepr(ext.value))
        else:
            out("Extension: ", myrepr(ext.oid), ext.critical and " (CRITICAL) " or " () ", myrepr(ext.value))
            if ext.critical:
                notice("Contained CRITICAL extension " + ext.oid.dotted_string.strip() + " which I don't recognize so in THEORY this is an invalid certificate. Maybe. Except x509 and standards so who knows.", line)

# Private key
def DumpPrivateKey(prefix, pemder):
    if pemder==None:
        return

    out = lambda text: orig_out(prefix, text, stdout=False)

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
        out("Private key was password protected, which will never work! - %s" % (e))
        return
    except ValueError as e:   # broken DER
        out("%s - data was %s (%i bytes)" % (e, repr(der[0:80]), len(der)))
        return
    except cryptography.exceptions.UnsupportedAlgorithm as e:
        out("%s - data was %s (%i bytes)" % (e, repr(der[0:80]), len(der)))
        return

    from cryptography.hazmat.primitives.asymmetric import dsa,rsa,ec
    if isinstance(key, rsa.RSAPrivateKey):
        out("RSA private key, %u bits" % (key.key_size))

    elif isinstance(key, dsa.DSAPrivateKey):
        out("DSA private key, %u bits" % (key.key_size))

    elif isinstance(key, ec.EllipticCurvePrivateKey):
        out("EC private key, %u bits" % (key.key_size))
        out("Curve name: " % (key.name))

    else:
        out("I don't know what type of key this is?! Tried RSA,DSA,EC.  : %s" % (repr(key)))
        return








#
# Output pass
#

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
            notice("Expected [ %s ] to have [ %s ] - it did not!", line)

    # Not latest firmware
    if re.match(r'\s*<SecurityGateway ', line):
        m = re.search(r' SchemaVersion="(([0-9]+)\.([0-9]+)\.([0-9]+))', line)
        if not m:
            notice("""Couldn't find a SchemaVersion="nn.nn.nn..." ?""", line)
        elif m.group(1) != "12.00.19":
            notice("Version is not 12.00.19 -- it was %s" % (m.group(1)), line)

        m = re.search(r' ConfigDate="([^"]+)', line)
        if not m:
            notice("""Couldn't find a ConfigDate="yyyy-mm-dd hh:mm:ss" ?""", line)
        else:
            delta = ( datetime.datetime.utcnow() - datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S") ).total_seconds()
            if delta < -3600*12:   # accept up to 12 timezones ahead
                notice("Config date is in the future?", line)
            elif delta > 3600*24*7*2:
                notice("Config date is %u weeks ago" % (delta/3600/24/7), line)

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
        notice("Rewriting Dest=0.0.0.0/0 to one IP. This might work for HTTP. Will likely _NOT_ work for HTTPS, because hostcert. Double check what they're trying to do.", line)

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
    # Certificate?
    #

    if re.match(r'\s*<Certificate ', line):
        DumpCertificate("CertificateData: ", re_group(r' CertificateData="([^"]+)"', line, 1, None) )
        DumpPrivateKey("PrivateKey: ", re_group(r' PrivateKey="([^"]+)"', line, 1, None) )


    #
    # Make note of major features
    #

    if re.match(r'\s*<HighAvailability ', line):
        addfeature("HA", line)
    if re.match(r'\s*<IPsecTunnel ', line):
        addfeature("IPsec Tunnels")
    if re.match(r'\s*<PipeRule ', line):
        addfeature("Pipe Rules")
    if re.match(r'\s*<IP(Rule|Policy) ', line):
        addfeature("Rules")
    if re.match(r'\s*<SLBPolicy ', line):
        addfeature("SLB", shorten(line))
    if re.match(r'\s*<LinkMonitor ', line):
        addfeature("LinkMonitor", shorten(line))

    subclass = "Routing"
    if re.match(r'\s*<Route .* RouteMonitor="True" ', line):
        addfeature("Route monitoring", shorten(line), subclass)
    if re.match(r'\s*<RouteBalancingInstance ', line):
        addfeature("Route Balancing", shorten(line), subclass)
    if re.match(r'\s*<LoopbackInterface ', line):
        addfeature("Route Balancing", shorten(line), subclass)
    if re.match(r'\s*<LinkAggregation ', line):
        addfeature("Link Aggregation", shorten(line), subclass)

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
    if v!=True:
        txt = "Info: Unused IPRuleSet: " + v[0]
        print(txt)
        out("<!-- " + txt + "-->")


#
# RE-DUMP ALL SETTINGS FOUND
#

out("")
out("<!-- ALL SETTINGS BELOW - USUALLY ONLY ONES CHANGED FROM DEFAULTS -->")
out("")
for txt in AllSettings:
    out("   " + txt)
out("")


#
# OUTPUT FEATURES IN USE
#

byclass = {}
for key,data in AllFeatures.items():
    c = data['subclass']
    if not c in byclass:
        byclass[c] = {}
    byclass[c][key] = data

for subclass,features in byclass.items():
out("")
    out("<!-- ", subclass or "MAJOR FEATURES", " -->")

    for key,data in features.items():
    out("")
    prefix = "    %-16s " % key
    indent = " " * len(prefix)
    if len(data['lines'])<1:
        out(prefix + str(data['count']))
    else:
        for desc in data['lines']:
            out(prefix + desc)
            prefix = indent
        if len(data['lines']) < data['count']:
            out("{}({} more)".format(indent, data['count']-len(data['lines'])))

out("")



#
# AT EOF: RE-DUMP NOTICES FOUND
#

if len(AllNotices)>0:
    out("", stdout=True)
    out("<!-- COPY OF NOTICES FOUND ABOVE: -->", stdout=True)

    NoticeCounts = {}
    header = "        NOTICE: "
    indent = "                "
    for i in AllNotices:
        text = i["text"]
        line= i.get("line")
        NoticeCounts[text] = NoticeCounts.get(text, 0) + 1

        if NoticeCounts[text] > 5:
            continue

        out("", stdout = True)
        if line:
            out("  " + line, stdout = True)
        out(header + re.sub(r"\n", "\n"+indent, text), stdout = True)

    out("", stdout = True)
    for text,n in NoticeCounts.items():
        if n>5:
            out("This notice occured %u more times:   (see inline for all)" % (n-5))
            out("    " + text)




out("<!-- EOF -->")

print("")
print("Done. Written to " + outfilename)
outfile.close()


for pf in [os.environ.get('ProgramW6432'), os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)')]:
    if pf:
        exe = pf + "\\Notepad++\\notepad++.exe"
        print(exe)
        if os.path.isfile(exe):
            print("   yes")
            subprocess.call( [exe, outfilename] )
