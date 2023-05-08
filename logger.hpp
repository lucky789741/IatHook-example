#pragma once
#include "includes.hpp"

class Logger {
    std::chrono::time_point<std::chrono::high_resolution_clock> start;
public:
    static Logger& getInstance();
    static const std::string AddressToHexString(PDWORD_PTR value);
    void print(const std::string&);
private:
    Logger();
};