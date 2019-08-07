module record_classes_types;

import std.stdio;
import std.exception : assumeUnique;

struct RecordLabel {
  bool valid;
  ushort length;
  string domain_name;
}

immutable string[ushort] RecordClasses; 
immutable string[ushort] RecordTypes;

static this() {
  string[ushort] t = [
    1: "INT",
    2: "CS",
    3: "CH",
    4: "HS"
  ];
  RecordClasses = assumeUnique(t);
  t = [
    0: "UNKNOWN",
    1: "A",
    2: "NS",
    3: "MD",
    4: "MF",
    5: "CNAME",
    6: "SOA",
    7: "MB",
    8: "MG",
    9: "MR",
    10: "NULL",
    11: "WKS",
    12: "PTR",
    13: "HINFO",
    14: "MINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    18: "AFSDB",
    42: "APL",
    257: "CAA",
    60: "CDNSKEY",
    59: "CDS",
    37: "CERT",
    49: "DHCID",
    32769: "DLV",
    39: "DNAME",
    48: "DNSKEY",
    43: "DS",
    55: "HIP",
    45: "IPSECKEY",
    25: "KEY",
    36: "KX",
    29: "LOC",
    35: "NAPTR",
    47: "NSEC",
    50: "NSEC3",
    51: "NSEC3PARAM",
    61: "OPENPGPKEY",
    46: "RRSIG",
    17: "RP",
    24: "SIG",
    33: "SRV",
    44: "SSHFP",
    32768: "TA",
    249: "TKEY",
    52: "TLSA",
    250: "TSIG",
    256: "URI",
    41: "OPT",
    255: "*"
  ];
  RecordTypes = assumeUnique(t);
}

