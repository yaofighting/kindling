//
// Created by siyao zhou on 2022/7/21.
//
#ifndef SYSDIG_SLOW_SYSCALL
#define SYSDIG_SLOW_SYSCALL
#include "sinsp.h"

struct SyscallElem{
    uint64_t timestamp;
    uint16_t type;
};

class slow_syscall{
    public:
        slow_syscall(sinsp *inspector):m_inspector(inspector){}
        ~slow_syscall();
        bool getTidExist(int tid);
        void erase(int tid);
        void insert(int tid, SyscallElem s);
        
    private:
        sinsp *m_inspector;
        unordered_map<int, SyscallElem> syscall_map;
};

#endif