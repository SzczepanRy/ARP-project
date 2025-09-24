/*
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <pcap.h>
#include <sstream>
#include <winsock2.h>
*/
// g++ main.cpp -IC:/Npcap-SDK/Include -LC:/Users/Szczepan/Desktop/code/share/CPP/ARPproject -lwpcap -lPacket -lws2_32 -o main.exe

#include "ARP.hpp"

int main() {
  ARPScaner();
  return 0;
}
