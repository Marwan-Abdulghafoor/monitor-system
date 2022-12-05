#include <string>

#include "format.h"


std::string Format::ElapsedTime(long seconds) {
    long mins = seconds / 60;
    long hrs = mins / 60;
    long sec = seconds - mins*60;
    mins = mins - hrs*60;

    std::string sec_ = std::to_string(sec);
    if(sec<10){
        sec_ = "0" + std::to_string(sec);
    }

    std::string mins_ = std::to_string(mins);
    if(mins<10){
        mins_ = "0" + std::to_string(mins);
    }

    std::string hrs_ = std::to_string(hrs);
    if(hrs<10){
        std::string hrs_ = "0" + std::to_string(hrs);
    }

    std::string time = hrs_ + ":" + mins_ + ":" + sec_;

    return time;
}