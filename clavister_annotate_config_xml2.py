
import os
import subprocess
import sys
import re
import io
import datetime
import base64
import binascii
import textwrap
import defusedxml

#sys.argv.append("c:/temp/tic-28025/config-cOS-Core-FW2-20190815.bak")
sys.argv.append("c:/temp/tic-27950/anonymous_config-FW-03-iDirect-20190807-v8598.bak")
# sys.argv.append("C:/Users/Mike/AppData/Local/Temp/config-fw1-20190624-v186.bak")

#sys.argv.append(r"C:\Users\miol\AppData\Local\Temp\config-HFW00024-20190830.bak")

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

filename = re.sub(r'\.html$', '', filename)   # for notepad++ "Run" on already-annotated file
print(sys.argv[0] + ": processing " + filename)

if re.search(r'\.bak', filename.lower()):
    with open(filename, "rb") as raw:
        rawdata = raw.read()
        assert rawdata[0:4]!="FPKG", ".bak file started with '" + str(rawdata[0:4]) + "', expected 'FPKG'"
        firstXmlLinePos = rawdata.find(b"<SecurityGateway")
        assert firstXmlLinePos>=0, "Could not find '<SecurityGateway' in file"
        lastXmlLinePos = rawdata.find(b"</SecurityGateway>")
        assert lastXmlLinePos>=0, "Could not find '</SecurityGateway>' in file"
        wholefiletext = rawdata[firstXmlLinePos:(lastXmlLinePos+18)].decode("utf-8")
else:
    with open(filename) as f:
        wholefiletext = f.read()

# Nonstandard HTML entities used in Clavister XML. Fix them first.
wholefiletext = re.sub(r'&num;', "&#35;", wholefiletext, flags=re.IGNORECASE)

import defusedxml.ElementTree as ET
try:
    root = ET.fromstring(wholefiletext, forbid_dtd=True, forbid_entities=True, forbid_external=True)
except ET.ParseError as e:
    print("There was an error reading/parsing the XML:")
    print("    " + str(e))
    (lineno,column) = e.position
    print("    (note that 'column' is where the XML entity starts, not where the error is)")
    print(wholefiletext.splitlines()[lineno-1])
    os._exit(1)

bytype = {}
addresses = {}
interfaces = {}
algs = {}
services = {}
settings = {}
logreceivers = {}
psks = {}
certificates = {}
routingtables = {}
others = {  # stuff we don't keep track of
    "EmailControlProfile": True,
    "WebProfile": True,
    "DNSProfile": True,
    "HTTPALGBanners": True,
    "HTTPAuthBanners": True,
    "GeolocationFilter": True,
    "ScheduleProfile": True,
    "AdvancedScheduleProfile": True,
    "SSHHostKey": True,
    "IKEAlgorithms": True,
    "IPsecAlgorithms": True,
    "LocalUserDatabase": True,
    "IGMPSetting": True,
}

def isearch(regex, text):
    return re.search(regex, text, flags=re.IGNORECASE)

def fly(parent, parentname):
    for elem in parent:
        if not elem.tag in bytype:
            bytype[elem.tag] = []
        bytype[elem.tag].append(elem)

        if isearch(r'Folder$', elem.tag) :
            fly(elem, parentname + elem.get('Name') + "/")

        elif elem.tag == "RoutingTable" :
            routingtables[elem.tag] = elem
            fly(elem, parentname + elem.get('Name') + "/")

        elif isearch(r'Address$', elem.tag ) or \
                isearch(r'^(IP[4-6])Group', elem.tag) or \
                elem.tag in ["FQDNGroup"]:
            addresses[ parentname + elem.get('Name') ] = elem
        elif isearch(r'Interface$', elem.tag ) or elem.tag in ["VLAN", "InterfaceGroup"]:
            interfaces[ parentname + elem.get('Name') ] = elem
        elif isearch(r'^Service', elem.tag ):
            services[ parentname + elem.get('Name') ] = elem
        elif isearch(r'^ALG_', elem.tag ):
            algs[ parentname + elem.get('Name') ] = elem
        elif isearch(r'^LogReceiver', elem.tag):
            logreceivers[ parentname + elem.get('Name') ] = elem
        elif elem.tag in ["PSK"]:
            psks[ parentname + elem.get('Name') ] = elem
        elif elem.tag in ["Certificate"]:
            certificates[ parentname + elem.get('Name') ] = elem
        elif isearch(r'Settings$', elem.tag ) or \
                isearch(r'^RemoteMgmt', elem.tag) or \
                elem.tag in ["DNS", "DateTime", "UpdateCenter", "HWM", "COMPortDevice"]:
            settings[elem.tag] = elem
        else:
            if elem.tag not in others:
                others[elem.tag] = elem
                print(f"What is a <{elem.tag}>?")


fly(root, "")

#
# Open outputfile and define out()
#

outfilename = filename + ".html"
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

def re_group(regex, string, group, default):
    m = re.search(regex, string)
    if not m:
        return default
    return m.group(group)

def shorten(text):
    return re.sub(r'="([^"]{20,})"', r'="\1..."', text)

def addfeature(key, desc = None):
    if type(desc) is str:
        desc = re.sub(r"^\s+", "", desc)
    if not key in AllFeatures:
        AllFeatures[key] = {'lines': [], 'count': 1}
    else:
        AllFeatures[key]['count'] += 1
    if desc and len(AllFeatures[key]['lines'])<3:
        AllFeatures[key]['lines'].append(desc)


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

def dhdesc(group, line, ispfs=False):
    ''' Return description of given group number. Will also notice() about problems, using the supplied line as context '''
    if re.match(r" *[Nn]one *$", group):
        if not ispfs:
            notice("Not using DH is not recommended. It MAY be acceptable for PFS, but we recommend at least group 5 and preferably group 14", line)
        return "None - don't use Diffie-Hellman key negotiation"

    try:
        igroup = int(group)
    except BaseException as e:
        return str(e)

    if not igroup or igroup not in dhdescs:
        return "UNKNOWN DIFFIE-HELLMAN GROUP " + group + " ?!"

    if (not ispfs) and igroup==1:
        notice("Diffie-Hellman group " + group + " (" + dhdescs[igroup] + ") is TRIVIALLY CRACKABLE. Use minimum 1536-bit MODP (group 5). For general use we recommend 2048-bit (group 14).", line)
    elif (not ispfs) and (1<igroup<5 or igroup==22):
        notice("Diffie-Hellman group " + group + " (" + dhdescs[igroup] + ") is no longer considered safe. Use minimum 1536-bit MODP (group 5). For general use we recommend 2048-bit (group 14).", line)
    elif 23<=igroup<=24:
        notice("Diffie-Hellman group " + group + " is considered suspect - possibly engineered to be unsafe. For general use we recommend 2048-bit (group 14). See https://tools.ietf.org/html/rfc8247#section-2.4", line)
    elif 16<=igroup<=18:
        notice("Diffie-Hellman group " + group + " (" + dhdescs[igroup] + ") is TOO LARGE and will cause excessive CPU load. Use maximum 3072-bit MODP (group 15). For general use we recommend 2048-bit (group 14).", line)
    return dhdescs[igroup]



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
    elif pubkey.key_size<1020:
        notice("Key size %u is TRIVIALLY CRACKABLE. Use at least 1536. Preferably 2048." % pubkey.key_size, line)
    elif pubkey.key_size<1530:
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
        if num0<28 or num1<28:  # in any decent-entropy PRNG
            notice("""Serial number 0x%x contains %u ones and %u zeroes. Expected 28+ of both.
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
# RE-DUMP ALL SETTINGS FOUND
#

out("")
out("<!-- ALL SETTINGS BELOW - USUALLY ONLY ONES CHANGED FROM DEFAULTS -->")
out("")
for name,elem in settings.items():
    elem.tail = None
    elem.text = None
    out("   ", ET.tostring(elem, encoding="unicode"))
    out("")
out("")


#
# OUTPUT FEATURES IN USE
#

out("")
out("<!-- MAJOR FEATURES -->")
for key,data in AllFeatures.items():
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
