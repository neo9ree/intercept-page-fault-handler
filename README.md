intercept-page-fault-handler
============================

Custom Page fault Handler for page fault side-channel attack in SGX environment.
It checks whether a page fault is invoked by side-channel attack or not.
If the page fault is from enclave, it sets corresponding page table entry as present
and make other EPC pages to be not present.

load.sh is to load the module while unload.sh is to unload the module.
