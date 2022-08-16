#include "slow_syscall.h"


void slow_syscall::getSlowSyscallTimeoutEvent(std::mutex *mtx){
    if(!m_timeout_list.empty()) return;
    chrono::nanoseconds ns = std::chrono::duration_cast< std::chrono::nanoseconds>(
		std::chrono::system_clock::now().time_since_epoch()
	);
    uint64_t cur = ns.count();
    int c = 0;
    std::lock_guard<std::mutex> guard(*mtx);
    unordered_map<int, SyscallElem>::iterator it = syscall_map.begin();
    while(it != syscall_map.end()){
        if((cur - it->second.timestamp) / 1e6 >= m_timeout){
            m_timeout_list.push_back(it->first);
            m_timeout_elems.push_back(it->second);
            syscall_map.erase(it++);
        }else{
            it++;
        }
    }
}

void slow_syscall::subSyscall(sinsp *inspector, map<string, ppm_event_type> &m_events){
    for(auto &e: m_events){
        if(e.first.length() >= 7 && e.first[0]=='s'&&e.first[1]=='y'&&e.first[2]=='s'&&e.first[3]=='c'&&e.first[4]=='a'&&e.first[5]=='l'&&e.first[6]=='l'){
            inspector->set_eventmask(e.second);
        }
    }
}