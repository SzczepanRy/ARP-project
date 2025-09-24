/*
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <pcap.h>
#include <sstream>
#include <winsock2.h>
*/
// g++ main.cpp -IC:/Npcap-SDK/Include
// -LC:/Users/Szczepan/Desktop/code/share/CPP/ARPproject -lwpcap -lPacket
// -lws2_32 -o main.exe

#include "ARP.hpp"
#include "TCP.hpp"




int main() {
  ARPScaner A;

  std::cout << "ppp\n";
  std::map<int, Host> res = A.GetResult();
  TCPScan T(res);



  return 0;
}
