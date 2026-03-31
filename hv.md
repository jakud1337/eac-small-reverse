# eac anti hypervisor detection

all from live dump easy anti cheat sys ida

---

## 1 cpuid timing attack

**sub** fffff803267c83b4  
**rva** 0x283b4  

big timing check

read irql  
set irql to 0f max so no interrupt no noise  

loop 1  
rdtsc  
cpuid leaf 1  
rdtsc  
store diff  

loop 2  
rdtsc  
rdtsc  
store diff  

100 times each  

restore irql  

**xref** -> sub fffff80326abf021  

both totals sent there  

compare with obf math  
0x84b42366f97b9e9a  
0x631189084772f068  

if cpuid too slow -> hypervisor  

normal cpu ~50 100 cycles  
vm ~500 2000  

**mitigation**  
fake rdtsc after vmexit so look normal  

---

## 2 cpuid vendor string

**sub** fffff803267fbe64  
**rva** 0x5be64  

cpuid leaf 0  

check vendor string  

compare xor obf constants  

genuineintel -> return 0  
authenticamd -> return 2  
other -> return 1 sus  

no need hook if vm return real cpu  

---

## 3 cpuid leaf 1 hypervisor bit

no big sub just cached cpuid  

ecx bit 31  

if 1 -> hypervisor  

**mitigation**  
clear bit in cache  
leaf01[2] &= ~(1 << 31)  

---

## 4 msr checks

### 4a hyper v msr

**sub** fffff803267fb87c  
**rva** 0x5b87c  

read msr 0x40000001  

if not zero -> hyper v  

**mitigation**  
inject gp fault for range 0x40000000+  

---

### 4b tsx ctrl check

**sub** fffff80326807534  
**rva** 0x67534  

read msr 0x122  
write back modified  
read again  

if value diff -> hypervisor blocked write  

**mitigation**  
dont intercept let hardware  

---

### 4c smi count

**sub** fffff803268ca000  
**rva** 0x12a000  

read msr 0x34  

weird values -> sus  

**mitigation**  
dont intercept  

---

### 4d amd perf

**sub** fffff803268c9f70  
**rva** 0x129f70  

amd only  

read perf msr  
use fences  

intel not affected  

---

### 4e amd sev

**sub** fffff8032687b8bc  
**rva** 0xdb8bc  

read msr 0xc80  

bit 0 set -> hypervisor  

amd only  

---

### 4f vmx msr

reads 0x480 to 0x491  

if non zero -> vmx present  

**mitigation**  
gp fault if hidden  

---

### 4g feature control

read msr 0x3a  

check vmx bits  

**mitigation**  
mask bits  

---

## 5 intel pt check

**sub** fffff80326899cac  
**rva** 0xf9cac  

this one heavy  

enable intel pt tracing  

setup buffer 2mb  
write msr 0x560 0x561  
enable tracing  

if no hide -> vmexit addr leak  

**mitigation**  
conceal vmx from pt  
stop pt on vmexit  
resume on entry  

---

## 6 cr4 vmxe

read cr4  

bit 13  

if set -> vmx  

**mitigation**  
mask in read shadow  

---

## 7 page table walk

**sub** fffff80326824a90  
**rva** 0x84a90  

manual walk  

read cr3  
walk tables  

check present nx etc  

**mitigation**  
ept identity map  

---

## 8 page integrity

**sub** fffff803268d446c  
**rva** 0x13446c  

compare api vs manual  

if exec hidden -> detect  

**mitigation**  
return blank not present  

---

## 9 physical memory scan

**subs**  
fffff8032680228c  
fffff80326802310  
fffff80326801e94  

scan all physical  

use sse compare  

search vm stuff  

**mitigation**  
hide with ept  
return zero  

---

## 10 export crc scan

**sub** fffff803268add08  
**rva** 0x10dd08  

scan exports  

crc32 compare  

**mitigation**  
no exports  

---

## 11 pool tag

check pool tags  

**mitigation**  
use ntfs tag  

---

## 12 sha1 module hash

hash code  

if modified -> detect  

**mitigation**  
no patch  
use ept exec redirect  

---

## 13 detection system

no local ban  

32 slots encrypted  

store results  

send to server  

server decide  

flag -> fffff803269ae820  

---

## 14 risk

low  
cpuid vendor msr mostly ok  

medium  
cpuid timing still tricky  
intel pt risky  

high  
vm interpreter  
wbinvd timing  
exceptions  

---

## 15 kpp boot check

big obf vm  

main in seg007  

check  
kernel path  
boot loader  
pe headers  
disk vs memory  
registry hash  

error codes  

0xc0020010 -> boot loader  
0xc0020011 -> kernel path  
0x40031000 -> kpp detect  

---

## important subs chain

get nt base  
sub fffff803268a9610  

get name  
sub fffff803268a9968  

pe header check  
sub fffff803267f1e74  

disk compare  
sub fffff8032680ce78  

hash registry  
sub fffff80326835818  

physical export walk  
sub fffff80326849300  

memory scan  
sub fffff803268aad80  

---

## why hv detected

even no patch  

problem -> ept blank pages  

page valid but zero  

eac see mismatch  

driver visible -> detect  
self signed -> sus  

---

## main issues

blank nonpaged pool -> detect  
vmx pages zero -> detect  

---

## fixes

dont blank pages in guest va  

use physical only memory  

unlink driver from list  

use contiguous memory vmx  

dont touch kernel  

---
