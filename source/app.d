import std.bitmanip;
import std.conv;
import std.stdio;
import std.socket;

import std.datetime.stopwatch : StopWatch;

import core.thread;
import core.sys.linux.ifaddrs;
import core.sys.linux.sys.socket;
import core.sys.linux.netinet.in_ : IP_ADD_MEMBERSHIP, IP_MULTICAST_LOOP;
import core.sys.posix.netdb;
import core.sys.posix.netinet.in_;

import record_classes_types;

class DnsSD {
  Socket sock;
  Address[] addrs;
  Address addr;
  this(string iface, string multicastGroupIP = "224.0.0.251", ushort port = 5353) {
    sock = new UdpSocket(AddressFamily.INET);
    sock.blocking = false;
    // detect ip address of iface
    string localHost = "";
    
    ifaddrs *ifaddr;
    ifaddrs *ifa;
    int family, s;

    if (getifaddrs(&ifaddr) == -1) 
    {
        writeln("getifaddrs");
    }
    for (ifa = ifaddr; ifa != null; ifa = ifa.ifa_next) {
        if (ifa.ifa_addr == null)
            continue;  
        auto host = new char[NI_MAXHOST];
        s=getnameinfo(ifa.ifa_addr,
            sockaddr_in.sizeof,
            host.ptr,
            NI_MAXHOST,
            null,
            0,
            NI_NUMERICHOST);
        if (s == 0)
        {
          string ifaceStr = "";
          auto i = ifa.ifa_name;
          while(*i) {
            ifaceStr ~= *i;
            i+= 1;
          }
          writeln("host? ", host);
          writeln("iface? ", ifaceStr);
          if (ifaceStr == iface) {
            localHost = cast(string) host;
          }
        }
    }

    InternetAddress localAddress;
    if (localHost != "") { 
      localAddress = new InternetAddress(localHost, port);
    } else {
      localAddress = new InternetAddress(port);
    }
    writeln("local host: ", localHost);
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


    addrs = getAddress(multicastGroupIP, port);
    addr = addrs[0];
    if (iface != "") {
      sock.setOption(SocketOptionLevel.SOCKET, cast(SocketOption)SO_BINDTODEVICE, cast(void[])iface);
      auto anyAddrs = getAddress("0.0.0.0", port);
      auto anyAddr = anyAddrs[0];
      sock.bind(anyAddr);
    } else {
      sock.bind(addr);
    }
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

      // parse
      result = parseRR(buf);
    }

    return result;
  }

  public void scanService(string service) {
    Record query;
    RecordResponse[string] ptrs;
    query.header.questions = 1;
    query.header.response = false;
    query.questions.length = 1;
    query.questions[0].label = service;
    query.questions[0].record_type = RecordTypes.ptr;
    query.questions[0].record_class = RecordClasses.int_;
    sendRecord(query);
    auto sw = StopWatch();
    sw.start();
    while(true) {
      auto dur = sw.peek();
      if (dur > 5000.msecs) {
        query.questions[0].label = service;
        sendRecord(query);
        sw.reset();
      }
      Thread.sleep(1.msecs);
      Record msg = processMessages();
      if (msg.valid) {
        if (!msg.header.response) continue;
        for (auto i = 0; i < msg.answers.length; i += 1) {
          auto ans = msg.answers[i];
          string label = ans.label;
          if (ans.record_type == RecordTypes.ptr) {
            Thread.sleep(100.msecs);
            string domain = ans.rdata.data;
            if ((domain in ptrs) is null) writeln(domain);
            ptrs[domain] = ans;
            query.questions[0].label = domain;
            sendRecord(query);
          }
        }
      }
    }
  }
}

void main(string[] args) {
  writeln("hello, friend\n", args);
  string service = "_services._dns-sd._udp.local";
  string iface = "";
  if (args.length > 1) {
   service = args[1];
  }
  if (args.length > 2) {
   iface = args[2];
  }

  auto resolver = new DnsSD(iface);
  resolver.scanService(service);

  /** example of response
    
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
   **/
}
