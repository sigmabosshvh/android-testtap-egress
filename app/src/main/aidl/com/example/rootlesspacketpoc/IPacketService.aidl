package com.example.rootlesspacketpoc;

interface IPacketService {
    int getUid() = 0;
    String runPoc() = 1;
    void destroy() = 16777114;
}