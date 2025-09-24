#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <pcap.h>
#include <sstream>
#include <winsock2.h>

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

int main() {
  pcap_if_t *alldevs, *dev;
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  std::cout << "init\n";
  // List available devices
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
    return 1;
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

  // Open device for sending packets
  handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
  if (!handle) {
    std::cerr << "Unable to open adapter: " << dev->name << std::endl;
    pcap_freealldevs(alldevs);
    return 1;
  }

  // ARP capture filter
  struct bpf_program fp;
  if (pcap_compile(handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
    std::cerr << "Error compiling filter\n";
    return 1;
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    std::cerr << "Error setting filter\n";
    return 1;
  }

  // Build Ethernet + ARP frame
  u_char packet[42]; // 14 (Ethernet) + 28 (ARP)

  ethernet_header *eth = (ethernet_header *)packet;
  arp_header *arp = (arp_header *)(packet + sizeof(ethernet_header));

  // Ethernet header
  memset(eth->dest, 0xff, 6); // Broadcast

  // get config
  std::ifstream file("config.txt");
  if (!file)
    return 1;

  u_char my_mac[6];
  u_char my_ip[4];
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
  memcpy(eth->src, my_mac, 6);

  eth->type = htons(0x0806); // ARP

  // ARP header
  arp->htype = htons(1);      // Ethernet
  arp->ptype = htons(0x0800); // IPv4
  arp->hlen = 6;              // MAC length
  arp->plen = 4;              // IP length
  arp->opcode = htons(1);     // ARP request

  memcpy(arp->sender_mac, my_mac, 6);

  memcpy(arp->sender_ip, my_ip, 4);

  for (int i = 1; i < 255; i++) {
    memset(arp->target_mac, 0x00, 6);
    u_char target_ip[4] = {192, 168, 1, (u_char)i};
    memcpy(arp->target_ip, target_ip, 4);

    // Send packet
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
      std::cerr << "Error sending ARP packet: " << pcap_geterr(handle)
                << std::endl;
    } else {
      //  printf("ARP request sent. to : 192.168.1.%d\n", i);
      /*
       struct pcap_pkthdr *header;
        const u_char *recv_packet;
        int res;
        */
    }
  }
  // listen
  struct pcap_pkthdr *header;
  const u_char *recv_packet;
  time_t start = time(nullptr);
  while (difftime(time(nullptr), start) < 5.0) { // listen 5 seconds
    int res = pcap_next_ex(handle, &header, &recv_packet);
    if (res <= 0)
      continue;

    ethernet_header *eth = (ethernet_header *)recv_packet;
    if (ntohs(eth->type) == 0x0806) {
      arp_header *arp_reply =
          (arp_header *)(recv_packet + sizeof(ethernet_header));
      if (ntohs(arp_reply->opcode) == 2) {
        printf("Reply from IP %d.%d.%d.%d MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               arp_reply->sender_ip[0], arp_reply->sender_ip[1],
               arp_reply->sender_ip[2], arp_reply->sender_ip[3],
               arp_reply->sender_mac[0], arp_reply->sender_mac[1],
               arp_reply->sender_mac[2], arp_reply->sender_mac[3],
               arp_reply->sender_mac[4], arp_reply->sender_mac[5]);
      }
    }
  }
  // Cleanup
  pcap_close(handle);
  pcap_freealldevs(alldevs);
  return 0;
}
