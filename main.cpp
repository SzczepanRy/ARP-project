// g++ main.cpp -IC:/Npcap-SDK/Include
// -LC:/Users/Szczepan/Desktop/code/share/CPP/ARPproject -lwpcap -lPacket
// -lws2_32 -o main.exe

#include "ARP.hpp"
#include "TCP.hpp"

int main() {
  ARPScaner A;
  std::map<int, Host> res = A.GetResult();
  TCPScan T(res);
  return 0;
}
