module record_classes_types;

import std.stdio;
import std.exception : assumeUnique;

struct RecordHeader {
  ushort id;
  ubyte qr, op, aa, tc, rd;
  ubyte ra, z, ad, cd, rc;
  ushort questions;
  ushort answers;
  ushort authorities;
  ushort additionals;
}

struct DnssdRecord {
  RecordHeader header;
  // TODO: arrays of answers, questions, authorities, etc
  // TODO: structs: Answer, Question, etc.. 
}

// TODO: structs for different record types

struct RecordLabel {
  bool valid;
  ushort length;
  string domain_name;
}

enum RecordClasses {
  unknown = 0,
  int_ = 1,
  cs = 2,
  ch = 3,
  hs = 4
};

enum RecordTypes {
  unknown = 0,
  a = 1,
  ns = 2,
  md = 3,
  mf = 4,
  cname = 5,
  soa = 6,
  mb = 7,
  mg = 8,
  mr = 9,
  null_ = 10,
  wks = 11,
  ptr = 12,
  hinfo = 13,
  minfo = 14,
  mx = 15,
  txt = 16,
  aaaa = 28,
  afsdb = 18,
  apl = 42,
  caa = 257,
  cdnskey = 60,
  cds = 59,
  cert = 37,
  dhcid = 49,
  dlv = 32769,
  dname = 39,
  dnskey = 48,
  ds = 43,
  hip = 55,
  ipseckey = 45,
  key = 25,
  kx = 36,
  loc = 29,
  naptr = 35,
  nsec = 47,
  nsec3 = 50,
  nsec3param = 51,
  openpgpkey = 61,
  rrsig = 46,
  rp = 17,
  sig = 24,
  srv = 33,
  sshfp = 44,
  ta = 32768,
  tkey = 249,
  tlsa = 52,
  tsig = 250,
  uri = 256,
  opt = 41,
  all = 255
};

shared static this() {
  // TODO: enum with values
}

