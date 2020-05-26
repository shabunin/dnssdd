import std.base64;
import std.bitmanip;
import std.conv;
import std.digest;
import std.stdio;
import std.socket;

import core.thread;
import core.sys.posix.netinet.in_;
import core.sys.linux.netinet.in_ : IP_ADD_MEMBERSHIP, IP_MULTICAST_LOOP;

import record_classes_types;

class DnsSD {
  Socket sock;
  Address addr;
  this(string multicastGroupIP = "224.0.0.251", ushort port = 5353) {
    sock = new UdpSocket(AddressFamily.INET);
    sock.blocking = false;
    InternetAddress localAddress = new InternetAddress(port);
    InternetAddress multicastGroupAddr = new InternetAddress(multicastGroupIP, port);

    struct ip_mreq {
      in_addr imr_multiaddr;   /* IP multicast address of group */
      in_addr imr_interface;   /* local IP address of interface */
    }
    ip_mreq addRequest;
    sockaddr_in local_sockaddr_in = cast(sockaddr_in)(*localAddress.name);
    sockaddr_in multi_sockaddr_in = cast(sockaddr_in)(*multicastGroupAddr.name);

    addRequest.imr_multiaddr = multi_sockaddr_in.sin_addr;
    addRequest.imr_interface = local_sockaddr_in.sin_addr;

    auto optionValue = (cast(char*)&addRequest)[0.. ip_mreq.sizeof];
    sock.setOption(SocketOptionLevel.IP, cast(SocketOption)IP_ADD_MEMBERSHIP, optionValue);
    auto addrs = getAddress(multicastGroupIP, port);
    addr = addrs[0];
    sock.bind(addr);
  }
  public void sendRecord(Record record) {
    ubyte[] result = serializeRR(record);

    sock.sendTo(result, addr);
  }
  public Record processMessages() {
    Record result;
    result.valid = false;
    ubyte[] buf;
    buf.length = 1024;
    auto receivedLen = sock.receive(buf);
    if(receivedLen > 0) {
      buf.length = receivedLen;
      writeln("##### ##### #### #### ##### #### #####");
      writeln("Received: ", buf.toHexString());
      writeln("##### ##### #### #### ##### #### #####");

      // parse
      result = parseRR(buf);
    }

    return result;
  }
}

void main() {
  writeln("hello, friend\n");

  auto resolver = new DnsSD();

  Record query;
  query.header.questions = 1;
  query.header.response = false;
  query.questions.length = 1;
  query.questions[0].label = "_services._dns-sd._udp.local";
  query.questions[0].record_type = RecordTypes.ptr;
  query.questions[0].record_class = RecordClasses.int_;
  resolver.sendRecord(query);
  Record resp;
  resp.header.answers = 1;
  resp.header.additionals = 3;
  resp.header.response = true;
  resp.header.authoritative = true;
  resp.answers.length = 1;
  resp.answers[0].label = "_batya._tcp.local";
  resp.answers[0].record_type = RecordTypes.ptr;
  resp.answers[0].record_class = RecordClasses.int_;
  resp.answers[0].label = "_batya._tcp.local";
  resp.answers[0].record_type = RecordTypes.ptr;
  resp.answers[0].record_class = RecordClasses.int_;
  resp.answers[0].ttl = 120;
  resp.answers[0].rdata.data = "_batya._tcp.local";
  resp.additionals.length = 3;
  resp.additionals[0].label = "_batya._tcp.local";
  resp.additionals[0].record_type = RecordTypes.a;
  resp.additionals[0].record_class = RecordClasses.int_;
  resp.additionals[0].ttl = 120;
  resp.additionals[0].rdata.data = "192.168.1.63";
  resp.additionals[1].label = "_batya._tcp.local";
  resp.additionals[1].record_type = RecordTypes.srv;
  resp.additionals[1].record_class = RecordClasses.int_;
  resp.additionals[1].ttl = 120;
  resp.additionals[1].rdata.port = 80;
  resp.additionals[2].label = "_batya._tcp.local";
  resp.additionals[2].record_type = RecordTypes.txt;
  resp.additionals[2].record_class = RecordClasses.int_;
  resp.additionals[2].ttl = 120;
  resp.additionals[2].rdata.data = "batya=big boldhead\njunior=small boldhead";
  resolver.sendRecord(resp);


  while(true) {
    try {
      auto rec = resolver.processMessages();
      if (rec.valid) {
        writeln(" ===== record parsed ===== ");
        writeln(rec);
        writeln(" ===== serialize:    ===== ");
        auto rrs = serializeRR(rec);
        writeln("##### ##### #### #### ##### #### #####");
        writeln("Serialized: ", rrs.toHexString());
        writeln("##### ##### #### #### ##### #### #####");
        auto r2 = parseRR(rrs);
        if (r2.valid) {
          writeln(" ===== serialized parsed ===== ");
        } else {
          writeln(" ===== serialized NOT valid ===");
        }
      }
      Thread.sleep(1.msecs);
    } catch (Exception e) {
      writeln("Exeption parsing message: ");
      writeln(e);
    } catch (Error e) {
      writeln("Error parsing message: ");
      writeln(e);
    }
  }
}
