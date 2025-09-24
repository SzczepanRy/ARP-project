#pragma once

#include <chrono>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "types.hpp"

class TCPScan {
public:
  WSADATA wsaData;
  sockaddr_in clientAddr{};
  SOCKET Socket;
  int t;

  TCPScan(std::map<int, Host> &addrs) {
    std::cout << "TCP init started\n";
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
      std::cerr << "WSAStartup failed\n";
      abort();
    }

    for (const auto &pair : addrs) {
      std::cout << "Key " << pair.first << " => ";
      std::cout << "IP: " << pair.second.ip << "\n";
      std::cout << "  MAC:" << pair.second.mac << "\n";
    }

    // this wee for thru
    int min;
    int max;


    std::cout << "Search what range \n";
    std::cout << "min : \n";
    std::cin >> min;
    std::cout << "max : \n";
    std::cin >> max;

int minTimeout = 50;
int maxTimeout = 100;
std::cout << "Recommended timeout: " << minTimeout << "-" << maxTimeout << " ms\n";
    std::cin >> t;




    for (const auto &pair : addrs) {
      std::cout << "scanning ip :" << pair.second.ip
                << " mac : " << pair.second.mac << "\n";
      for (int i = min; i <= max; i++) {
        this->Socket = this->createTcpSocket();
        u_long mode = 1; // non-blocking
        ioctlsocket(Socket, FIONBIO, &mode);

        clientAddr.sin_family = AF_INET;
        clientAddr.sin_port = htons(i);
        inet_pton(AF_INET, pair.second.ip.c_str(), &clientAddr.sin_addr);
        connectSocket(i ,pair.second.ip );
        std::this_thread::sleep_for(
            std::chrono::milliseconds(10)); // wait up to timeout
        closesocket(Socket);
      }
    }
  }

  SOCKET createTcpSocket() {
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
      std::cerr << "Socket creation failed: " << WSAGetLastError() << "\n";
      WSACleanup();
      abort();
    }
    return serverSocket;
  }

  void connectSocket( int port , std::string ip) {
    int result = connect(Socket, (SOCKADDR *)&clientAddr, sizeof(clientAddr));

    if (result == SOCKET_ERROR) {
      int err = WSAGetLastError();
      if (err == WSAEWOULDBLOCK) {
        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(Socket, &writeSet);

        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = t * 1000;

        int sel = select(0, nullptr, &writeSet, nullptr, &timeout);
        if (sel > 0 && FD_ISSET(Socket, &writeSet)) {
          std::cout << "Port " << port << " open on " << ip<< "\n";
        }
      }
    } else {
      std::cout << "Port " << port << " open on " << ip << "\n";
    }

    closesocket(Socket);

  }

  ~TCPScan() {
    closesocket(Socket);
    WSACleanup();
  }
};
