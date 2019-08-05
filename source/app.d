import std.stdio;
import std.socket;
import std.bitmanip;
import core.sys.posix.netinet.in_;
import core.sys.linux.netinet.in_ : IP_ADD_MEMBERSHIP, IP_MULTICAST_LOOP;


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
      writeln("is data, len: ", receivedLen);

      // TODO: comments and docs

      // parse labels
      struct Label {
        bool valid;
        ushort length;
        char[] domain_name;
      }
      Label _parseLabel(ubyte[] buf, int offset) {
        // TODO: reverse engineering
        char[][] labels;
        // length of array
        ushort length = 0;
        bool valid = true;
        while(true) {
          auto label_len = buf.peek!ubyte(offset + length);
          if ((label_len & 0b11000000) == 0b11000000) {
            // compression. rfc1035 4.1.4
            auto i = buf.peek!ushort(offset + length) & 0b0011111111111111;
            auto parsed = _parseLabel(buf, i);
            if (parsed.length > 0) {
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
              auto label = cast(char[]) buf[offset + length..offset+length+label_len];
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

        char[] domain_name;
        domain_name = "".dup;
        for (auto j = 0, m = labels.length; j < m; j += 1) {
          if (j > 0) {
            domain_name ~= ".";
          }
          domain_name ~= labels[j];
        }

        Label result;
        result.valid = valid;
        result.length = length;
        result.domain_name = domain_name;

        return result;
      }

      // parse general
      void _parse(ubyte[] buf) {
        if (buf.length <= 12) {
          return;
        }
        writeln("========= start, len: ", buf.length);
        ushort[string] header;
        header["id"] = buf.read!ushort();
        ubyte ub = buf.read!ubyte();
        header["qr"] = (ub & 0b11111111) >> 7;
        header["op"] = (ub & 0b01111000) >> 3;
        header["aa"] = (ub & 0b00000100) >> 2;
        header["tc"] = (ub & 0b00000010) >> 1;
        header["rd"] = (ub & 0b00000001) >> 0;
        ub = buf.read!ubyte();
        header["ra"] = (ub & 0b10000000) >> 7;
        header["z"]  = (ub & 0b01000000) >> 6;
        header["ad"] = (ub & 0b00100000) >> 6;
        header["cd"] = (ub & 0b00010000) >> 5;
        header["rc"] = (ub & 0b00001111) >> 0;
        header["questions"] = buf.read!ushort();
        header["answers"] = buf.read!ushort();
        header["authorities"] = buf.read!ushort();
        header["additionals"] = buf.read!ushort();
        if (header["tc"] != 0 ||
            header["rd"] != 0 ||
            header["ra"] != 0 ||
            header["z"] != 0 ||
            header["ad"] != 0 ||
            header["cd"] != 0 ||
            header["rc"] != 0) {
          writeln(">>>> some from [tc, rd, ra, z, ad, cd, rc] header elements is not 0");
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

        auto offset = 0;
        auto current_record_item = 0;
        while(current_record_item < record_count_list.length) {
          auto parsed = _parseLabel(buf, offset);
          writeln("parsed: ", parsed);

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
            auto type_value = buf.peek!ushort(offset);
            offset += 2;
            auto csl_value = buf.peek!ushort(offset);
            offset += 2;
            writeln("questin for: ", parsed.domain_name);
            writeln("type: ", type_value, " csl: ", csl_value);
          } else {
            if (offset + 10 > buf.length) {
              break;
            }
            auto type_value = buf.peek!ushort(offset);
            offset += 2;
            auto csl_value = buf.peek!ushort(offset);
            auto flash = csl_value & 0b1000000000000000;
            offset += 2;
            auto ttl = buf.peek!uint(offset);
            offset += 4;
            auto rdlen = buf.peek!ushort(offset);
            offset += 2;
            if (offset + rdlen > buf.length) {
              break;
            }
            offset += rdlen;
            writeln("answer for: ", parsed.domain_name);
            writeln("type: ", type_value, " csl: ", csl_value);
            writeln("ttl: ", ttl, " rdlen: ", rdlen);
          }

          record_count_list[current_record_item].count--;
          if (record_count_list[current_record_item].count <= 0) {
            current_record_item += 1;
          }
        }

        writeln("end >>>>");
      }
      _parse(buf);
    } else {
      // no data
    }
  }
}
