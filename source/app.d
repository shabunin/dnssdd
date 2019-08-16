import std.base64;
import std.bitmanip;
import std.conv;
import std.stdio;
import std.socket;

import core.sys.posix.netinet.in_;
import core.sys.linux.netinet.in_ : IP_ADD_MEMBERSHIP, IP_MULTICAST_LOOP;

import record_classes_types;

void main()
{
  Socket sock = new UdpSocket(AddressFamily.INET);
  sock.blocking = false;
  auto multicastGroupIP = "224.0.0.251";
  ushort port = 5353;
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
  auto adr = getAddress(multicastGroupIP, port);
  sock.bind(adr[0]);
  sock.sendTo("hello, friend\n", adr[0]);

  writeln("hello, friend\n");

  while (true)
  {
    ubyte[] buf;
    buf.length = 1024;
    auto receivedLen = sock.receive(buf);
    if(receivedLen > 0)
    {
      buf.length = receivedLen;

      // TODO: comments and docs

      // parse labels
      RecordLabel _parseLabel(ubyte[] buf, int offset) {
        // TODO: reverse engineering
        string[] labels;
        // length of bytes
        ushort length = 0;
        bool valid = true;
        while(true) {
          auto label_len = buf.peek!ubyte(offset + length);
          if ((label_len & 0b11000000) == 0b11000000) {
            // compression rfc1035 4.1.4
            auto i = buf.peek!ushort(offset + length) & 0b0011111111111111;
            // recursion
            auto parsed = _parseLabel(buf, i);
            if (parsed.valid) {
              labels.length += 1;
              labels[$ - 1] = parsed.domain_name;
              length += 2;
              break;
            } else {
              valid = false;
              break;
            }
          } else if ((label_len & 0b11000000) == 0b00000000) {
            length += 1;
            if (label_len == 0x00) {
              break;
            } else if (offset + length + label_len <= buf.length) {
              auto label = cast(string) buf[offset + length..offset+length+label_len];
              labels.length += 1;
              labels[$ - 1] = label;
              length += label_len;
            } else {
              valid = false;
              break;
            }
          } else {
            valid = false;
            break;
          }
        }

        string domain_name;
        domain_name = "".dup;
        for (auto j = 0, m = labels.length; j < m; j += 1) {
          if (j > 0) {
            domain_name ~= ".";
          }
          domain_name ~= labels[j];
        }

        RecordLabel result;
        result.valid = valid;
        result.length = length;
        result.domain_name = domain_name;

        return result;
      }

      void _parseRdataA(ubyte[] buf, int offset, int len) {
        string result;
        result = "".dup;
        for (int i = 0; i < len; i += 1) {
          ubyte octet = buf.peek!ubyte(offset + i);
          result ~= to!string(octet, 10);
          if(i != len - 1) {
            result ~= ".";
          }
        }
        writeln("_parseRdataA: ", result);
      }

      void _parseRdataAAAA(ubyte[] buf, int offset, int len) {
        string result;
        result = "".dup;
        for (int i = 0; i < len; i += 2) {
          ushort octet = buf.peek!ushort(offset + i);
          result ~= to!string(octet, 16);
          if(i != len - 2) {
            result ~= ":";
          }
        }
        writeln("_parseRdataAAAA: ", result);
      }

      void _parseRdataPtr(ubyte[] buf, int offset, int len) {
        string result;
        RecordLabel parsed = _parseLabel(buf, offset);
        if (parsed.valid) {
          result = parsed.domain_name;
        }
        writeln("_parseRdataPtr: ", result);
      }

      void _parseRdataTxt(ubyte[] buf, int offset, int len) {
        string result;
        result = "".dup;

        int i = 0;
        while (i < len) {
          ubyte blen = buf.peek!ubyte(offset + i);
          i += 1;
          if (i + blen <= len) {
            string pair = cast(string) buf[offset + i..offset + i + blen];
            result ~= pair;
            result ~= "\n";
            i += blen;
          } else {
            break;
          }
        }
        writeln("_parseRdataTxt: ", result);
      }

      void _parseRdataSrv(ubyte[] buf, int offset, int len) {
        if (len <= 6) {
          return;
        }
        string target = "".dup;
        RecordLabel parsed = _parseLabel(buf, offset + 6);
        if (parsed.valid) {
          target = cast(string) parsed.domain_name;
        }
        ushort priority = buf.peek!ushort(offset);
        ushort weight = buf.peek!ushort(offset + 2);
        ushort port = buf.peek!ushort(offset + 4);
        writeln("_parseRdataSrv:: ", target);
        writeln("priority: ", priority, ", weight: ", weight, " port: ", port);
      }

      void _parseRdataOther(ubyte[] buf, int offset, int len) {
        string result;
        result = Base64.encode(buf[offset..offset + len]);
        writeln("_parseRdataOther: ", result);
      }

      // parse general
      void _parse(ubyte[] buf) {
        if (buf.length <= 12) {
          return;
        }
        writeln("========= start, len: ", buf.length);
        ushort[string] header;
        header["id"] = buf.peek!ushort(0);

        ubyte ub = buf.peek!ubyte(2);
        header["qr"] = (ub & 0b11111111) >> 7;
        header["op"] = (ub & 0b01111000) >> 3;
        header["aa"] = (ub & 0b00000100) >> 2;
        header["tc"] = (ub & 0b00000010) >> 1;
        header["rd"] = (ub & 0b00000001) >> 0;
        ub = buf.peek!ubyte(3);
        header["ra"] = (ub & 0b10000000) >> 7;
        header["z"]  = (ub & 0b01000000) >> 6;
        header["ad"] = (ub & 0b00100000) >> 6;
        header["cd"] = (ub & 0b00010000) >> 5;
        header["rc"] = (ub & 0b00001111) >> 0;
        header["questions"] = buf.peek!ushort(4);
        header["answers"] = buf.peek!ushort(6);
        header["authorities"] = buf.peek!ushort(8);
        header["additionals"] = buf.peek!ushort(10);
        if (header["tc"] != 0 ||
            header["rd"] != 0 ||
            header["ra"] != 0 ||
            header["z"] != 0 ||
            header["ad"] != 0 ||
            header["cd"] != 0 ||
            header["rc"] != 0) {
          writeln(">>>> some from [tc, rd, ra, z, ad, cd, rc] header elements is not 0");
          writeln();
          return;
        }
        auto sum = header["questions"];
        sum += header["answers"];
        sum += header["authorities"];
        sum += header["additionals"];
        if (sum == 0) {
          // no payload?
          writeln(">>>> there is no payload questions/authorities/additionals/answers");
          return;
        }
        writeln(header);
        //writeln(buf);

        // count list that server to iterate over record entries
        struct string_ushort {
          string name;
          ushort count;
        }
        string_ushort[] record_count_list;
        record_count_list.length = 4;
        auto count = 0;
        string[] keys = ["questions", "answers", "authorities", "additionals"];
        for (auto k = 0, m = keys.length; k < m; k += 1) {
          auto key = keys[k];
          auto cnt = header[key];
          if (cnt > 0) {
            record_count_list[count].name = key;
            record_count_list[count].count = cnt;
            count += 1;
          }
        }
        record_count_list.length = count;

        auto offset = 12;
        auto current_record_item = 0;
        while(current_record_item < record_count_list.length) {
          auto parsed = _parseLabel(buf, offset);
          if (parsed.valid) {
            offset += parsed.length;
          } else {
            //invalid = true;
            break;
          }

          auto record_key = record_count_list[current_record_item].name;
          if (record_key == "questions") {
            if (offset + 4 > buf.length) {
              break;
            }
            string record_type = "".dup;
            string record_class = "".dup;
            ushort type_value = buf.peek!ushort(offset);
            writeln("type_value: ", type_value);
            if ((type_value in RecordTypes) !is null) {
              record_type = RecordTypes[type_value];
            }
            writeln("type: ", record_type);
            offset += 2;
            ushort cls_value = buf.peek!ushort(offset);
            writeln("cls_value: ", cls_value);
            if ((cls_value in RecordClasses) !is null) {
              record_class = RecordClasses[cls_value];
            }
            offset += 2;
            writeln("questin for: ", parsed.domain_name);
            writeln("type: ", record_type, " class: ", record_class);
          } else {
            string record_type = "".dup;
            string record_class = "".dup;
            if (offset + 10 > buf.length) {
              break;
            }
            ushort type_value = buf.peek!ushort(offset);
            if ((type_value in RecordTypes) !is null) {
              record_type = RecordTypes[type_value];
            }
            offset += 2;
            ushort cls_value = buf.peek!ushort(offset);
            ushort cls_key = cls_value & 0b0111111111111111;
            if ((cls_key in RecordClasses) !is null) {
              record_class = RecordClasses[cls_key];
            }
            ushort flash = cls_value & 0b1000000000000000;
            offset += 2;
            auto ttl = buf.peek!uint(offset);
            offset += 4;
            auto rdlen = buf.peek!ushort(offset);
            offset += 2;
            if (offset + rdlen > buf.length) {
              break;
            }
            if (record_type == "A") {
              _parseRdataA(buf, offset, rdlen);
            } else if (record_type == "AAAA") {
              _parseRdataAAAA(buf, offset, rdlen);
            }else if (record_type == "PTR") {
              _parseRdataPtr(buf, offset, rdlen);
            } else if (record_type == "TXT") {
              _parseRdataTxt(buf, offset, rdlen);
            } else if (record_type == "SRV") {
              _parseRdataSrv(buf, offset, rdlen);
            } else {
              _parseRdataOther(buf, offset, rdlen);
            }
            offset += rdlen;
            writeln(record_key, " for: ", parsed.domain_name);
            writeln("type: ", record_type, " class: ", record_class, " flash: ", flash);
            writeln("ttl: ", ttl, " rdlen: ", rdlen);
          }

          record_count_list[current_record_item].count--;
          if (record_count_list[current_record_item].count <= 0) {
            current_record_item += 1;
          }
        }

        writeln("end >>>>", offset, ">>", buf.length);
        writeln();
      }
      _parse(buf);
    } else {
      // no data
    }
  }
}
