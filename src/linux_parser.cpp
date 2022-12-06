#include <dirent.h>
#include <unistd.h>
#include <string>
#include <vector>

#include "linux_parser.h"

using std::stof;
using std::string;
using std::to_string;
using std::vector;

string LinuxParser::OperatingSystem() {
  string line;
  string key;
  string value;
  std::ifstream filestream(kOSPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ' ', '_');
      std::replace(line.begin(), line.end(), '=', ' ');
      std::replace(line.begin(), line.end(), '"', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "PRETTY_NAME") {
          std::replace(value.begin(), value.end(), '_', ' ');
          return value;
        }
      }
    }
  }
  return value;
}

string LinuxParser::Kernel() {
  string os, version, kernel;
  string line;
  std::ifstream stream(kProcDirectory + kVersionFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> os >> version >> kernel;
  }
  return kernel;
}

vector<int> LinuxParser::Pids() {
  vector<int> pids;
  DIR* directory = opendir(kProcDirectory.c_str());
  struct dirent* file;
  while ((file = readdir(directory)) != nullptr) {
    // Is this a directory?
    if (file->d_type == DT_DIR) {
      // Is every character of the name a digit?
      string filename(file->d_name);
      if (std::all_of(filename.begin(), filename.end(), isdigit)) {
        int pid = stoi(filename);
        pids.push_back(pid);
      }
    }
  }
  closedir(directory);
  return pids;
}

float LinuxParser::MemoryUtilization() { 
  std::string line, key, memory;
  float result, TotalMemory, FreeMemory;
  std::ifstream filestream(kProcDirectory + kMeminfoFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ':', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> memory) {
        if (key == "MemTotal") { TotalMemory = std::stof(memory);}
        if (key == "MemFree") { FreeMemory = std::stof(memory);}
      }
    }
  }
  result = (TotalMemory - FreeMemory)/TotalMemory;
  return result;

 }

long LinuxParser::UpTime() { 
  std::string line, time;
  std::ifstream filestream(kProcDirectory + kUptimeFilename);
  if (filestream.is_open()) {
    std::getline(filestream, line);
    std::istringstream linestream(line);
    linestream >> time;
  }
  return std::stol(time);
 }

float LinuxParser::CpuUtilization() { 
  float ans;
  std::string line, cpu;
  string user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
  std::ifstream filestream(kProcDirectory + kStatFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ':', ' ');
      std::istringstream linestream(line);
      while (linestream >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice) {
        if (cpu == "cpu"){
          int nonIdle = std::stol(user) + std::stol(nice) + std::stol(system) + std::stol(irq) + std::stol(softirq) + std::stol(steal);
          int idle_ = std::stol(idle) + std::stol(iowait);
          ans = nonIdle / (float) (nonIdle+idle_);
        }
      }
    }
  }
  return ans;
 }

 float LinuxParser::CpuUtilization(int process_id) { 
  float output;
  string value;
  float seconds, totalTime;
  std::string line;
  float uTime, sTime, cuTime, csTime, startTime;
  long uptime = LinuxParser::UpTime();
  std::ifstream filestream(kProcDirectory + "/" + std::to_string(process_id) + kStatFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      for(int i=1; i<= 22; i++){
          linestream >> value;
          if(i==14 ){
            uTime = std::stof(value);
          }
          if(i==15){
            sTime = std::stof(value);
          }
          if(i==16){
            cuTime = std::stof(value);
          } 
          if(i==17){
            csTime = std::stof(value);
          } 
          if(i==22){
            startTime = std::stof(value);
          }
      }
    }
  }
  totalTime = (uTime + sTime + cuTime + csTime) / (float) sysconf(_SC_CLK_TCK);
  seconds = uptime - (startTime / (float) sysconf(_SC_CLK_TCK));
  output = totalTime / seconds;
  return output;
 }

int LinuxParser::TotalProcesses() { 
  std::string line, key, processes;
  int numOfProcesses;
  std::ifstream filestream(kProcDirectory + kStatFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      while (linestream >> key >> processes) {
        if (key == "processes") { numOfProcesses = std::stoi(processes);}
      }
    }
  }
  return numOfProcesses;
}

int LinuxParser::RunningProcesses() { 
  std::string line, key, processes;
  int numOfRunningProcesses;
  std::ifstream filestream(kProcDirectory + kStatFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      while (linestream >> key >> processes) {
        if (key == "procs_running") { numOfRunningProcesses = std::stoi(processes);}
      }
    }
  }
  return numOfRunningProcesses;
 }


string LinuxParser::Command(int pid) { 
  string output;
  std::ifstream filestream(kProcDirectory + std::to_string(pid) + kCmdlineFilename);
  if (filestream.is_open()) {
    std::getline(filestream, output);
  }
  return output;
}


string LinuxParser::Ram(int pid) { 
  std::string line, key;
  long ram;
  std::ifstream filestream(kProcDirectory + "/" + std::to_string(pid) + kStatusFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      linestream >> key;
      if (key == "VmSize:") { 
        linestream >> ram;
        break;
      }
    }
  }
  return std::to_string(ram/1024);  
}


string LinuxParser::Uid(int pid) {
  std::string line, key, output;
  std::ifstream filestream(kProcDirectory + "/" + std::to_string(pid) + kStatusFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      linestream >> key;
      if (key == "Uid:") { 
        linestream >> output;
        break;
      }
    }
  }
  return output;  
}


string LinuxParser::User(int pid) { 
  std::string line, user, password, userId;
  std::ifstream filestream(kPasswordPath);
  string Uid = LinuxParser::Uid(pid);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ':', ' ');
      std::istringstream linestream(line);
      while (linestream >> user >> password >> userId) {
        if (userId == Uid) { break;}
      }
    }
  }
  return user; 
}


long LinuxParser::UpTime(int pid) { 
  std::string line, value;
  long time;
  std::ifstream filestream(kProcDirectory + std::to_string(pid) + kStatFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      for (int i=0; i <= 22; i++) {
        linestream >> value;
        if (i == 21) {
          time = std::stol(value) / sysconf(_SC_CLK_TCK);
        }
      }
    }
  }
  return time; 
}
