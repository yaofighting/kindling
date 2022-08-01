#include "slow_syscall.h"


void slow_syscall::getSlowSyscallTimeoutEvent(){
    if(!m_timeout_list.empty()) return;
    chrono::nanoseconds ns = std::chrono::duration_cast< std::chrono::nanoseconds>(
		std::chrono::system_clock::now().time_since_epoch()
	);
    int64_t cur = ns.count();
    for(auto &e: syscall_map){
        if((cur - e.second.timestamp) / 1e6 >= m_timeout){
            m_timeout_list.push_back(e.first);
            syscall_map.erase(e.first);
        }
    }
}