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
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
//#define round 280
#define round 41000

MODULE_INFO(version, "0.1");
MODULE_AUTHOR("Me");
MODULE_LICENSE("GPL");
 
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

/* Callback function */
void test_skcipher_cb(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS)
        return;
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
}

/* Perform cipher operation */
unsigned int test_skcipher_encdec(struct skcipher_def *sk,
                     int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_skcipher_encrypt(sk->req);
    else
        rc = crypto_skcipher_decrypt(sk->req);

    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n",
            rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

/* Initialize and trigger cipher operation */
static int test_skcipher(void)
{
    unsigned long flags;
    uint64_t start, end,initial, value=0;
    unsigned int cycles_low, cycles_high, cycles_low1, cycles_high1;
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *scratchpad = NULL;
    char *ivdata = NULL;
    //unsigned char key[32]="ABCDEFGHABCDEFGHABCDEFGHABCDEFGH";
    unsigned char key[32];
    int ret = -EFAULT;

    skcipher = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_skcipher_cb,
                      &sk.result);

    /* AES 256 with random key */
    get_random_bytes(&key, 32);
    if (crypto_skcipher_setkey(skcipher, key, 32)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* IV will be random */
    ivdata = kmalloc(16, GFP_KERNEL);
    if (!ivdata) {
        pr_info("could not allocate ivdata\n");
        goto out;
    }
    get_random_bytes(ivdata, 16);
    //ivdata="abcdefghabcdefgh";

    /* Input data will be random */
    scratchpad = kmalloc(16, GFP_KERNEL);
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }
    get_random_bytes(scratchpad, 16);
    //scratchpad="1234567812345678";

    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, scratchpad, 16);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
    init_completion(&sk.result.completion);


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
	
	initial=x86_rdmsr(0x639);
	while(initial==(value=x86_rdmsr(0x639)));
	asm volatile (  "CPUID\n\t"
                        "RDTSC\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r"
        (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");

        /* encrypt data */
        ret = test_skcipher_encdec(&sk, 1);
	
        asm volatile(   "RDTSCP\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t"
                        "CPUID\n\t": "=r" (cycles_high1), "=r"
        (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");
	start = ( ((uint64_t)cycles_high << 32) | cycles_low );
        end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
	printk(KERN_INFO "rdmsr changes: %llu, time=%llu",(x86_rdmsr(0x639)-value),end-start);
        raw_local_irq_restore(flags);
        preempt_enable();


 

    if (ret)
        goto out;

    pr_info("Encryption triggered successfully\n");

out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (ivdata)
        kfree(ivdata);
    if (scratchpad)
        kfree(scratchpad);
    return ret;
}


void inline Filltimes(unsigned int count) {
unsigned long flags;
 uint64_t start, end,initial, value=0;
unsigned cycles_low, cycles_high, cycles_low1, cycles_high1;
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
	
	initial=x86_rdmsr(0x639);
	while(initial==(value=x86_rdmsr(0x639)));
	//value=x86_rdmsr(0x639);
	asm volatile (  "CPUID\n\t"
                        "RDTSC\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r"
        (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");

	  for (i=0;i<count;i++)
	    //x86_rdmsr(0x639);
	    x86_nop();
	
        asm volatile(   "RDTSCP\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t"
                        "CPUID\n\t": "=r" (cycles_high1), "=r"
        (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");
	//printk(KERN_INFO "rdmsr changes: %s   ",(value==x86_rdmsr(0x639)?"No":"Yes"));
	printk(KERN_INFO "rdmsr changes: %llu",(x86_rdmsr(0x639)-value));
        raw_local_irq_restore(flags);
        preempt_enable();


start = ( ((uint64_t)cycles_high << 32) | cycles_low );

end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
 printk(KERN_INFO "time=%llu, rdmsr performed=%d\n",end-start,count);
}

static int __init hello_start(void)
{
 // int i=0;
  //for (i=0;i<100;i++)
  //  Filltimes(round);
  test_skcipher();
  return;
}

static void __exit hello_end(void)
{
 printk(KERN_INFO "Goodbye Mr.\n");
}

module_init(hello_start);
module_exit(hello_end);


