#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <pcap.h>
#include <sstream>
#include <vector>
#include <winsock2.h>

#include "types.hpp"

struct ethernet_header {
  u_char dest[6];
  u_char src[6];
  u_short type;
};

struct arp_header {
  u_short htype;
  u_short ptype;
  u_char hlen;
  u_char plen;
  u_short opcode;
  u_char sender_mac[6];
  u_char sender_ip[4];
  u_char target_mac[6];
  u_char target_ip[4];
};

class ARPScaner {
public:
  pcap_if_t *alldevs, *dev;
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  // packet values  (ETH & ARP)
  u_char packet[42]; // 14 (Ethernet) + 28 (ARP)

  ethernet_header *eth = (ethernet_header *)packet;
  arp_header *arp = (arp_header *)(packet + sizeof(ethernet_header));

  // read values
  u_char my_mac[6];
  u_char my_ip[4];

  // result
  std::map<int, Host> Result;

  ARPScaner() {
    listDevices();
    openDevice();
    captureFilter();
    std::cout << "reading file\n";
    readFile();
    std::cout << "building frame\n";
    buildFrame();

    std::cout << "sending querys\n";
    sendQuerys();

    std::cout << "listening\n";
    listen(2);
  }

  void listDevices() {
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
      std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
    }

    int i = 0;
    for (dev = alldevs; dev != nullptr; dev = dev->next) {
      std::cout << i << ": " << dev->name;
      if (dev->description)
        std::cout << " - " << dev->description;
      std::cout << std::endl;
      i++;
    }

    int choice;
    std::cout << "Select device index: ";
    std::cin >> choice;

    dev = alldevs;
    for (int j = 0; j < choice; j++)
      dev = dev->next;
  }

  void openDevice() {
    handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
    if (!handle) {
      std::cerr << "Unable to open adapter: " << dev->name << std::endl;
      pcap_freealldevs(alldevs);
    }
  }

  void captureFilter() {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
      std::cerr << "Error compiling filter\n";
    }
    if (pcap_setfilter(handle, &fp) == -1) {
      std::cerr << "Error setting filter\n";
    }
  }

  void readFile() {
    std::ifstream file("config.txt");
    if (!file)
      std::cerr << "error reading file\n";

    std::stringstream buffer;
    buffer << file.rdbuf(); // read whole file into stringstream
    std::string content = buffer.str();
    content.erase(0, content.find_first_not_of(" \t\n\r"));
    content.erase(content.find_last_not_of(" \t\n\r") + 1);
    std::cout << "content  : " << content << " content len " << content.length()
              << "\n";

    std::stringstream buff(content);
    for (int i = 0; i < 2; i++) {
      std::string val;
      std::getline(buff, val, '|');

      std::stringstream ss(val);
      if (i == 0) {
        for (int j = 0; j < 6; j++) {
          std::string bytestr;
          std::getline(ss, bytestr, ':');

          my_mac[j] = static_cast<u_char>(std::stoi(bytestr, nullptr, 16));
        }
      } else if (i == 1) {
        for (int j = 0; j < 4; j++) {
          std::string byteStr;
          std::getline(ss, byteStr, '.');

          my_ip[j] = static_cast<u_char>(std::stoi(byteStr, nullptr, 10));
        }
      }
    }

    file.close();
  }

  void buildFrame() {

    // Build Ethernet + ARP frame
    // Ethernet header
    memset(eth->dest, 0xff, 6); // Broadcast

    eth->type = htons(0x0806); // ARP

    // ARP header
    arp->htype = htons(1);      // Ethernet
    arp->ptype = htons(0x0800); // IPv4
    arp->hlen = 6;              // MAC length
    arp->plen = 4;              // IP length
    arp->opcode = htons(1);     // ARP request

    memcpy(arp->sender_mac, my_mac, 6);

    memcpy(arp->sender_ip, my_ip, 4);
  }

  void sendQuerys() {

    std::vector<int> octets;
    while (true) {

      std::cout
          << "provide the three first octets of network [ex: 192.168.1]: \n";
      std::string input;
      std::cin >> input;

      std::stringstream stream(input);
      std::string octet;

      while (std::getline(stream, octet, '.')) {
        int number = std::atoi(octet.c_str());
        octets.push_back(number);
      }

      if (octets.size() == 3) {
        break;
      } else {
        std::cout << "Wrong input\n";
      }
    }

    for (int i = 1; i < 255; i++) {
      memset(arp->target_mac, 0x00, 6);
      u_char target_ip[4] = {(u_char)octets[0], (u_char)octets[1], (u_char)octets[2], (u_char)i};
      memcpy(arp->target_ip, target_ip, 4);

      // Send packet
      if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        std::cerr << "Error sending ARP packet: " << pcap_geterr(handle)
                  << std::endl;
      } else {
        //  printf("ARP request sent. to : 192.168.1.%d\n", i);
      }
    }
  }

  void listen(int timeout) {
    struct pcap_pkthdr *header;
    const u_char *recv_packet;
    time_t start = time(nullptr);
    int id = 0;
    while (difftime(time(nullptr), start) < timeout) { // listen X seconds
      int res = pcap_next_ex(handle, &header, &recv_packet);
      if (res <= 0)
        continue;

      ethernet_header *eth = (ethernet_header *)recv_packet;
      if (ntohs(eth->type) == 0x0806) {
        arp_header *arp_reply =
            (arp_header *)(recv_packet + sizeof(ethernet_header));
        if (ntohs(arp_reply->opcode) == 2) {

          std::stringstream ip_ss;
          for (int i = 0; i < 4; ++i) {
            ip_ss << static_cast<int>(arp_reply->sender_ip[i]);
            if (i < 3)
              ip_ss << ".";
          }
          Result[id].ip = ip_ss.str();

          std::stringstream mac_ss;
          for (int i = 0; i < 6; ++i) {
            mac_ss << std::hex << std::uppercase << std::setw(2)
                   << std::setfill('0')
                   << static_cast<int>(arp_reply->sender_mac[i]);
            if (i < 5)
              mac_ss << ":";
          }
          Result[id].mac = mac_ss.str();
          id += 1;
        }
      }
    }
  }

  std::map<int, Host> GetResult() { return Result; }

  ~ARPScaner() {
    // Cleanup
    pcap_close(handle);
    pcap_freealldevs(alldevs);
  }
};
