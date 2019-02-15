#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/hardirq.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <linux/moduleparam.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/delay.h>
#define round 500
#define crypto_round 4096
//#define round 41000

MODULE_INFO(version, "0.1");
MODULE_AUTHOR("Chen Liu");
MODULE_LICENSE("GPL");

unsigned int cycles_low, cycles_high, cycles_low1, cycles_high1;
unsigned long flags;
uint64_t initial, value=0;
uint64_t start, end;
 
uint64_t inline x86_rdmsr(uint64_t msr)
{
	uint32_t low, high;
	asm volatile (
		"rdmsr"
		: "=a"(low), "=d"(high)
		: "c"(msr)
	);
	return ((uint64_t)high << 32) | low;
}

void inline x86_wrmsr(uint64_t msr, uint64_t value)
{
	uint32_t low = value & 0xFFFFFFFF;
	uint32_t high = value >> 32;
	asm volatile (
		"wrmsr"
		:
		: "c"(msr), "a"(low), "d"(high)
	);
}

void inline x86_nop(void)
{
        asm volatile (
		"nop"
		:
		:
	);
}

struct tcrypt_result {
    struct completion completion;
    int err;
};

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

void print_hex(const char *s)
{ 
  int i;
  for (i=0;i<16;i++)
    printk(KERN_INFO "%02x", (unsigned char)s[i]);
  printk(KERN_INFO "\n");
}

#pragma GCC push_options
#pragma GCC optimize ("O0")
/* Initialize and trigger cipher operation */
static uint64_t test_cipher(void)
{
    
    int i;
    cycles_low=0;
    cycles_high=0;
    cycles_low1=0;
    cycles_high1=0;
    struct crypto_cipher *cipher = NULL;
    char buf[16]="AAAAAAAAAAAAAAAA";
    //char buf[16]="DDDDDDDDDDDDDDDD";
    char key[16]="BBBBBBBBBBBBBBBB";
    //char key[16]="CCCCCCCCCCCCCCCC";
    char buf_cipher[16]="XXXXXXXXXXXXXXXX";

    int ret = -EFAULT;

    cipher = crypto_alloc_cipher("aes-asm", 0, 0);
    if (IS_ERR(cipher)) {
        pr_info("could not allocate cipher handle\n");
        return PTR_ERR(cipher);
    }

    /* AES 128 with random key */
   // get_random_bytes(&key, 16);
    if (crypto_cipher_setkey(cipher, key, 16)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

	//pr_info("Plaintext size:%u",(unsigned int)strlen(buf));
	//print_hex(buf);
    /* We encrypt one block */

	asm volatile ("CPUID\n\t"
	"RDTSC\n\t"
	"mov %%edx, %0\n\t"
	"mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
	"%rax", "%rbx", "%rcx", "%rdx");
	asm volatile("RDTSCP\n\t"
	"mov %%edx, %0\n\t"
	"mov %%eax, %1\n\t"
	"CPUID\n\t": "=r" (cycles_high1), "=r" (cycles_low1):: "%rax",
	"%rbx", "%rcx", "%rdx");
	asm volatile ("CPUID\n\t"
	"RDTSC\n\t"
	"mov %%edx, %0\n\t"
	"mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
	"%rax", "%rbx", "%rcx", "%rdx");
	asm volatile("RDTSCP\n\t"
	"mov %%edx, %0\n\t"
	"mov %%eax, %1\n\t"
	"CPUID\n\t": "=r" (cycles_high1), "=r" (cycles_low1):: "%rax",
	"%rbx", "%rcx", "%rdx");



 	preempt_disable();
  	raw_local_irq_save(flags);
	
	initial=x86_rdmsr(MSR_PP0_ENERGY_STATUS);
	while(initial==(value=x86_rdmsr(MSR_PP0_ENERGY_STATUS)));
	initial=value;
	asm volatile (  "CPUID\n\t"
                        "RDTSC\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r"
        (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");

        /* encrypt data */
	//for (i=0;i<250000;i++)
	//	x86_nop();
	//for (i=0;i<10000;i++)
        //	crypto_cipher_encrypt_one(cipher,buf_cipher,buf);
	udelay(650);	
	

	//while(initial==(value=x86_rdmsr(MSR_PP0_ENERGY_STATUS)));
        asm volatile(   "RDTSCP\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t"
                        "CPUID\n\t": "=r" (cycles_high1), "=r"
        (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");
	start = ( ((uint64_t)cycles_high << 32) | cycles_low );
        end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
	value=x86_rdmsr(MSR_PP0_ENERGY_STATUS);
	printk(KERN_INFO "rdmsr changes: %llu, time=%llu",(value-initial),end-start);
	raw_local_irq_restore(flags);
	preempt_enable();


    if (ret)
        goto out;

    //pr_info("Encryption triggered successfully\n");

out:
    if (cipher)
        crypto_free_cipher(cipher);
   /* if (buf)
        kfree(buf);*/
    // while(!encryption_done);
	//pr_info("Ciphertext:");
	//print_hex(buf);
    return (value-initial);
}

void inline Filltimes(unsigned int count) {
	unsigned long flags;
	uint64_t start,end,initial, value=0;
	cycles_low=cycles_high=cycles_low1=cycles_high1=0;
	volatile int i = 0;

	asm volatile ("CPUID\n\t"
	"RDTSC\n\t"
	"mov %%edx, %0\n\t"
	"mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
	"%rax", "%rbx", "%rcx", "%rdx");
	asm volatile("RDTSCP\n\t"
	"mov %%edx, %0\n\t"
	"mov %%eax, %1\n\t"
	"CPUID\n\t": "=r" (cycles_high1), "=r" (cycles_low1):: "%rax",
	"%rbx", "%rcx", "%rdx");
	asm volatile ("CPUID\n\t"
	"RDTSC\n\t"
	"mov %%edx, %0\n\t"
	"mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
	"%rax", "%rbx", "%rcx", "%rdx");
	asm volatile("RDTSCP\n\t"
	"mov %%edx, %0\n\t"
	"mov %%eax, %1\n\t"
	"CPUID\n\t": "=r" (cycles_high1), "=r" (cycles_low1):: "%rax",
	"%rbx", "%rcx", "%rdx");



        preempt_disable();
        raw_local_irq_save(flags);
	
	initial=x86_rdmsr(MSR_PP0_ENERGY_STATUS);
	while(initial==(value=x86_rdmsr(MSR_PP0_ENERGY_STATUS)));
	//value=x86_rdmsr(0x639);
	asm volatile (  "CPUID\n\t"
                        "RDTSC\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r"
        (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");

	  for (i=0;i<count;i++)
	    x86_rdmsr(MSR_PP0_ENERGY_STATUS);
	  //  x86_nop();
	
        asm volatile(   "RDTSCP\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t"
                        "CPUID\n\t": "=r" (cycles_high1), "=r"
        (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");
	//printk(KERN_INFO "rdmsr changes: %s   ",(value==x86_rdmsr(0x639)?"No":"Yes"));
	printk(KERN_INFO "rdmsr changes: %llu",(x86_rdmsr(MSR_PP0_ENERGY_STATUS)-value));
        raw_local_irq_restore(flags);
        preempt_enable();


start = ( ((uint64_t)cycles_high << 32) | cycles_low );

end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
 printk(KERN_INFO "time=%llu, rdmsr performed=%d\n",end-start,count);
}
#pragma GCC pop_options
static int __init hello_start(void)
{
  int i=0;
  uint64_t data=0;
  for (i=0;i<crypto_round;i++){
  //Filltimes(i);
  	data+=test_cipher();
  }
	pr_info("average energy consumption: %llu",data>>12);
  return 0;
}

static void __exit hello_end(void)
{
 printk(KERN_INFO "Goodbye Mr.\n");
}

module_init(hello_start);
module_exit(hello_end);


