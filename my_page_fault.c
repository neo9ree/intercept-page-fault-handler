#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <asm/traps.h>
#include <asm/desc_defs.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>

//PGFAULT_NR is the interrupt number of page fault. It is platform specific.
#if defined(CONFIG_X86_64)
#define PGFAULT_NR X86_TRAP_PF
#else
#error This module is only for X86_64 kernel
#endif

static unsigned long new_idt_table_page;
static struct desc_ptr default_idtr;

//addresses of some symbols
static unsigned long addr_dft_page_fault = 0UL; //address of default 'page_fault'
static unsigned long addr_dft_do_page_fault = 0UL; //address of default 'do_page_fault'
static unsigned long addr_pv_irq_ops = 0UL; //address of 'pv_irq_ops'
static unsigned long addr_adjust_exception_frame; //content of pv_irq_ops.adjust_exception_frame, it's a function
static unsigned long addr_error_entry = 0UL;
static unsigned long addr_error_exit = 0UL;

module_param(addr_dft_page_fault, ulong, S_IRUGO);
module_param(addr_dft_do_page_fault, ulong, S_IRUGO);
module_param(addr_pv_irq_ops, ulong, S_IRUGO);
module_param(addr_error_entry, ulong, S_IRUGO);
module_param(addr_error_exit, ulong, S_IRUGO);

#define CHECK_PARAM(x) do{\
    if(!x){\
        printk(KERN_INFO "my_virt_drv: Error: need to set '%s'\n", #x);\
        is_any_unset = 1;\
    }\
    printk(KERN_INFO "my_virt_drv: %s=0x%lx\n", #x, x);\
}while(0)

static int check_parameters(void){
    int is_any_unset = 0;
    CHECK_PARAM(addr_dft_page_fault);
    CHECK_PARAM(addr_dft_do_page_fault);
    CHECK_PARAM(addr_pv_irq_ops);
    CHECK_PARAM(addr_error_entry);
    CHECK_PARAM(addr_error_exit);
    return is_any_unset;
}

typedef void (*do_page_fault_t)(struct pt_regs*, unsigned long);

void my_do_page_fault(struct pt_regs* regs, unsigned long error_code){
    struct task_struct * task = current;
    void * fault_addr = 0;
    pgd_t * pgd;
    pud_t * pud;
    pmd_t * pmd;
    pte_t * ptep;
    pte_t pte;
    uint64_t one = 1;
    uint64_t reserved_bit = (one << 50) | (one << 51);
    uint64_t ignored_bit = (one << 9);
    uint8_t * enclave_base = 0x7fffe8000000;
    uint64_t enclave_size = 0x8000000;
    uint64_t i = 0;
    uint64_t cnt = 0;
    int is_code_page = 1;
    uint64_t code_start_offset = 0x262d000;
    uint64_t code_size = 0x2000000;
    uint64_t data_start_offset = 0x4655000;
    //uint64_t data_start_offset = 0x462d000;

    asm("mov %%cr2, %0" : "=r" (fault_addr));
    //printk(KERN_INFO "my_virt_drv: page fault %p detected in process %lu.\n", fault_addr, (unsigned long)task->pid);
    //printk(KERN_INFO "my_virt_drv: fault_addr 0x%p pt_regs.ip 0x%llx detected in process %lu\n", fault_addr, regs->ip, (unsigned long)task->pid);
    pgd = pgd_offset(current->mm, (unsigned long)fault_addr);

    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        //printk(KERN_INFO "my_virt_drv: pgd bad value\n");
        goto out;
    }

    pud = pud_offset(pgd, fault_addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        //printk(KERN_INFO "my_virt_drv: pud bad value\n");
        goto out;
    }

    pmd = pmd_offset(pud, fault_addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        //printk(KERN_INFO "my_virt_drv: pmd bad value\n");
        goto out;
    }

    ptep = pte_offset_map(pmd, fault_addr);
    if (!ptep) {
        printk(KERN_INFO "my_virt_drv: ptep is NULL\n");
    }

    pte = *ptep;
    //printk(KERN_INFO "my_virt_drv: pte is %llx\n", pte);


    if (pte.pte & reserved_bit) {
        pte_t * first_target_ptep = NULL;

        ptep->pte = ptep->pte ^ reserved_bit;
        if(!pte_present(pte))
            ptep->pte = ptep->pte | one;

        printk(KERN_INFO "my_virt_drv: fault_addr 0x%p pt_regs.ip 0x%llx detected in process %lu\n", fault_addr, regs->ip, (unsigned long)task->pid);
        if(!((uint64_t)fault_addr >= (uint64_t)enclave_base + 0x0 && (uint64_t)fault_addr <= (uint64_t)enclave_base + data_start_offset)){
            is_code_page = 0;
        }

        if (is_code_page == 0) {
            uint8_t * fault_addr_masked = (uint64_t)fault_addr & 0xfffffffff000;
            //printk(KERN_INFO "data: fault_addr 0x%p pt_regs.ip 0x%llx detected in process %lu\n", fault_addr, regs->ip, (unsigned long)task->pid);
            for (i=data_start_offset / 0x1000; i<enclave_size/0x1000; i++) {
            //for (i=0x220000 / 0x1000; i<enclave_size/0x1000; i++) {
                uint64_t * target_addr = enclave_base + i * 0x1000;
                pgd_t * pgd_tmp;
                pud_t * pud_tmp;
                pmd_t * pmd_tmp;
                pte_t * ptep_tmp;
                pte_t pte_tmp;

                first_target_ptep = NULL;
/*
                if (target_addr ==  fault_addr_masked || \
                        target_addr == fault_addr_masked - 0x1000 || \
                        target_addr == fault_addr_masked + 0x1000) {// when target_addr = 0xabcabc000, fault_addr = 0xabcabcfff, it keeps invalidating its fault_addr. So we have to mask llower 12bits of fault_addr and compare it with target_addr

                    //printk(KERN_INFO, "target_addr : %p, fault_addr : %p\n", target_addr, fault_addr);
                    continue;
                }
*/
                if (target_addr == 0x7fffec644000 || target_addr == 0x7fffec643000)
                    continue;
                if (target_addr == fault_addr_masked)
                    continue;
                pgd_tmp = pgd_offset(current->mm, (unsigned long)target_addr);
                if (pgd_none(*pgd_tmp) || pgd_bad(*pgd_tmp)) {
                    continue;
                }

                pud_tmp = pud_offset(pgd_tmp, target_addr);
                if (pud_none(*pud_tmp) || pud_bad(*pud_tmp)) {
                    continue;
                }

                pmd_tmp = pmd_offset(pud_tmp, target_addr);
                if (pmd_none(*pmd_tmp) || pmd_bad(*pmd_tmp)) {
                    continue;
                }

                ptep_tmp = pte_offset_map(pmd_tmp, target_addr);
                if (!ptep_tmp) {
                    pte_unmap(ptep_tmp);
                    continue;
                }

                if (pte_present(*ptep_tmp) && (ptep_tmp->pte & ignored_bit)) { // if there's already visited page, mark it as fault
                    //printk(KERN_INFO "AAAAAAAAAAAAAAAAAAAA target_addr is %p\n",  target_addr);
                    cnt += 1;
                    ptep_tmp->pte = ptep_tmp->pte ^ reserved_bit;
                    ptep_tmp->pte = ptep_tmp->pte ^ one;
                    pte_unmap(ptep_tmp);
                }
            }
            //printk(KERN_INFO "AAAAAAAAA fault_addr is 0x%p cnt is %llu\n", fault_addr, cnt);
            pte_unmap(ptep);
            return;
        }

        //printk(KERN_INFO "my_virt_drv: fault_addr 0x%p pt_regs.ip 0x%llx detected in process %lu\n", fault_addr, regs->ip, (unsigned long)task->pid);

        if ((uint64_t)fault_addr & 0xfffffffff000 != (uint64_t)fault_addr) {
            ptep->pte = ptep->pte ^ ignored_bit; // Don't make this address fault again
            return;
        }

        // for code section
        for (i=code_start_offset/0x1000; i<=(code_start_offset+code_size)/0x1000; i++) {
        //for (i=0x220000/0x1000; i<enclave_size/0x1000; i++) {
            uint64_t * target_addr = enclave_base + i * 0x1000;
            pgd_t * pgd_tmp;
            pud_t * pud_tmp;
            pmd_t * pmd_tmp;
            pte_t * ptep_tmp;
            pte_t pte_tmp;
            uint8_t * fault_addr_masked = (uint64_t)fault_addr & 0xfffffffff000;

            first_target_ptep = NULL;

            /*
            if (target_addr == fault_addr_masked || \
                    target_addr == fault_addr_masked - 0x1000 || \
                    target_addr == fault_addr_masked + 0x1000) {// when target_addr = 0xabcabc000, fault_addr = 0xabcabcfff, it keeps invalidating its fault_addr. So we have to mask llower 12bits of fault_addr and compare it with target_addr

                //printk(KERN_INFO, "target_addr : %p, fault_addr : %p\n", target_addr, fault_addr);
                continue;
            }
            */
            if (target_addr == fault_addr_masked)
                continue;

            pgd_tmp = pgd_offset(current->mm, (unsigned long)target_addr);
            if (pgd_none(*pgd_tmp) || pgd_bad(*pgd_tmp)) {
                continue;
            }

            pud_tmp = pud_offset(pgd_tmp, target_addr);
            if (pud_none(*pud_tmp) || pud_bad(*pud_tmp)) {
                continue;
            }

            pmd_tmp = pmd_offset(pud_tmp, target_addr);
            if (pmd_none(*pmd_tmp) || pmd_bad(*pmd_tmp)) {
                continue;
            }

            ptep_tmp = pte_offset_map(pmd_tmp, target_addr);
            if (!ptep_tmp) {
                pte_unmap(ptep_tmp);
                continue;
            }

            if (pte_present(*ptep_tmp) && (ptep_tmp->pte & ignored_bit)) { // if there's already visited page, mark it as fault
                //printk(KERN_INFO "fault_addr is %p, target_addr is %p\n", fault_addr, target_addr);
                cnt += 1;
                ptep_tmp->pte = ptep_tmp->pte ^ reserved_bit;
                ptep_tmp->pte = ptep_tmp->pte ^ one;
                pte_unmap(ptep_tmp);
            }
        }

        //printk(KERN_INFO "fault_addr is 0x%p cnt is %llu\n", fault_addr, cnt);
        //error_code = error_code ^ (1 << 3); // PF_RSVD;
        pte_unmap(ptep);
        return;
    }


out:
    pte_unmap(ptep);
    ((do_page_fault_t)addr_dft_do_page_fault)(regs, error_code);
}

asmlinkage void my_page_fault(void);
asm("   .text");
asm("   .type my_page_fault,@function");
asm("my_page_fault:");
asm("   .byte 0x66");
asm("   xchg %ax, %ax");
asm("   callq *addr_adjust_exception_frame");
asm("   sub $0x78, %rsp");
asm("   callq *addr_error_entry");
asm("   mov %rsp, %rdi");
asm("   mov 0x78(%rsp), %rsi");
asm("   movq $0xffffffffffffffff, 0x78(%rsp)");
asm("   callq my_do_page_fault");
asm("   jmpq *addr_error_exit");
asm("   nopl (%rax)");

//this function is copied from kernel source
static inline void pack_gate(gate_desc *gate, unsigned type, unsigned long func,
                         unsigned dpl, unsigned ist, unsigned seg){
    gate->offset_low    = PTR_LOW(func);
    gate->segment       = __KERNEL_CS;
    gate->ist       = ist;
    gate->p         = 1;
    gate->dpl       = dpl;
    gate->zero0     = 0;
    gate->zero1     = 0;
    gate->type      = type;
    gate->offset_middle = PTR_MIDDLE(func);
    gate->offset_high   = PTR_HIGH(func);
}

static void my_load_idt(void *info){
    struct desc_ptr *idtr_ptr = (struct desc_ptr *)info;
    load_idt(idtr_ptr);
}

static int my_fault_init(void){
    //check all the module_parameters are set properly
    if(check_parameters())
        return -1;
    //get the address of 'adjust_exception_frame' from pv_irq_ops struct
    addr_adjust_exception_frame = *(unsigned long *)(addr_pv_irq_ops + 0x30);
    return 0;
}

int register_my_page_fault_handler(void){
    struct desc_ptr idtr;
    gate_desc *old_idt, *new_idt;
    int retval;

    //first, do some initialization work.
    retval = my_fault_init();
    if(retval)
        return retval;

    //record the default idtr
    store_idt(&default_idtr);

    //read the content of idtr register and get the address of old IDT table
    old_idt = (gate_desc *)default_idtr.address; //'default_idtr' is initialized in 'my_virt_drv_init'

    //allocate a page to store the new IDT table
    printk(KERN_INFO "my_virt_drv: alloc a page to store new idt table.\n");
    new_idt_table_page = __get_free_page(GFP_KERNEL);
    if(!new_idt_table_page)
        return -ENOMEM;

    idtr.address = new_idt_table_page;
    idtr.size = default_idtr.size;
    
    //copy the old idt table to the new one
    new_idt = (gate_desc *)idtr.address;
    memcpy(new_idt, old_idt, idtr.size);
    pack_gate(&new_idt[PGFAULT_NR], GATE_INTERRUPT, (unsigned long)my_page_fault, 0, 0, __KERNEL_CS);
    
    //load idt for all the processors
    printk(KERN_INFO "my_virt_drv: load the new idt table.\n");
    load_idt(&idtr);
    printk(KERN_INFO "my_virt_drv: new idt table loaded.\n");
    smp_call_function(my_load_idt, (void *)&idtr, 1); //wait till all are finished
    printk(KERN_INFO "my_virt_drv: all CPUs have loaded the new idt table.\n");
    return 0;
}

void unregister_my_page_fault_handler(void){
    struct desc_ptr idtr;
    store_idt(&idtr);
    //if the current idt is not the default one, restore the default one
    if(idtr.address != default_idtr.address || idtr.size != default_idtr.size){
        load_idt(&default_idtr);
        smp_call_function(my_load_idt, (void *)&default_idtr, 1);
        free_page(new_idt_table_page);
    }
}

MODULE_LICENSE("Dual BSD/GPL");
