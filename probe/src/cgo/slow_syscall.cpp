#include "slow_syscall.h"

bool slow_syscall::getTidExist(int tid){
    return syscall_map.find(tid) != syscall_map.end();
}

void slow_syscall::erase(int tid){
    syscall_map.erase(tid);
}

void slow_syscall::insert(int tid, SyscallElem s){
    syscall_map[tid] = s;
}