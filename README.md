# nfs_perf_mon

Tool to help diagnose which NFS client might be overloading backend storage. NFS implementation inependent since it picks NFS syscalls out of the network traffic to the server. Tracks bandwidth, iops, and packet count. 

## requirements

libpcap and libjson-c (needed for PBS integration)
