#include <unistd.h>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "process.h"
#include "linux_parser.h"

using std::string;
using std::to_string;
using std::vector;

Process::Process(int pid) : processId(pid) {}

int Process::Pid() const { return processId; }

float Process::CpuUtilization() const { return LinuxParser::CpuUtilization(Pid()); }

string Process::Command() { return LinuxParser::Command(Pid()); }

string Process::Ram() { return (LinuxParser::Ram(Pid())); }

string Process::User() { return LinuxParser::User(Pid()); }

long int Process::UpTime() { return LinuxParser::UpTime(Pid()); }

bool Process::operator<(Process const& a) const { return a.CpuUtilization() < CpuUtilization(); }