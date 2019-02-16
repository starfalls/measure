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
#include <crypto/akcipher.h>
#include <linux/scatterlist.h>
#define round 500
//#define round 41000

MODULE_INFO(version, "0.1");
MODULE_AUTHOR("Chen Liu");
MODULE_LICENSE("GPL");

unsigned int cycles_low, cycles_high, cycles_low1, cycles_high1;
unsigned long flags;
uint64_t initial, value=0;
unsigned int encryption_done=0;
uint64_t start, end;
const char priv_key[] =
    "\x30\x82\x02\x5d\x02\x01\x00\x02\x81\x81\x00\xd0"
    "\xb4\x5a\xc1\x9e\x2e\x4d\xae\xbd\x51\x39\xcc\x4b"
    "\x12\xf5\x76\x30\xcf\x39\x97\xf1\xd3\x0d\xaa\x37"
    "\x70\x2d\x2f\x01\xc9\x69\x09\xe3\x4e\xd5\x90\x68"
    "\xfe\xbf\x7c\x8b\x86\xdf\xf3\x14\xb3\x96\xcf\x1b"
    "\x39\xe3\xe6\x8a\x77\x6d\xe4\x89\xef\xdb\xba\x4a"
    "\x40\x6d\xa9\xec\x21\x62\x00\xa4\xc3\x45\xcc\xdd"
    "\x56\xb2\x77\x59\x46\x17\x27\x0e\x2c\xfe\x85\x53"
    "\x72\x26\x9b\xdc\x24\x83\xd1\x67\xa7\x4c\x88\x70"
    "\x78\x3f\x1c\x60\xd4\x95\x14\x57\xfc\xdb\x15\xaa"
    "\xab\x31\x32\xb2\x44\x72\xdd\xb0\x0b\x13\x62\x03"
    "\x50\x1d\xd4\x6a\xf6\xb2\x23\x02\x03\x01\x00\x01"
    "\x02\x81\x80\x7b\x83\x10\xe6\xde\xf7\x26\x30\x10"
    "\x88\x3e\x7d\x61\xbc\xa1\x99\xc5\xbf\x0d\xa5\x97"
    "\x8e\xc0\xda\x88\x9e\x91\x8e\xed\x2e\xc6\x43\xfc"
    "\xcb\x0d\xe6\xbd\xcc\x6d\x84\x86\x8a\x56\x84\xe4"
    "\x2e\x78\x44\xaf\x27\x2e\x71\xa4\x66\x93\x99\x99"
    "\xec\x62\x8c\x38\x1f\x33\x06\x37\xc1\x9d\x17\x6b"
    "\xad\xfb\x8e\x44\xd3\x11\xcb\x74\xa4\x01\x78\xb0"
    "\x9c\x64\xd3\x0d\x63\x99\x65\xe3\xca\xae\x11\xb2"
    "\xc4\x00\x36\xc2\xfc\x4b\x7b\x6f\x9e\x84\xb6\x97"
    "\x00\x56\x5b\x09\xa1\x28\xf5\x28\x8d\xc7\x93\x45"
    "\xba\xc0\x6b\xa9\x2d\xeb\x02\xcd\xde\x1e\x29\x02"
    "\x41\x00\xf6\x0e\x41\xbc\xfa\x40\x82\xba\xa0\x6a"
    "\xa5\x75\x5c\xcd\xfe\xa8\x11\xa6\xef\xbc\xad\x5f"
    "\x86\x40\xb4\x5a\x65\xc1\x7b\x5e\x89\xc2\x60\x38"
    "\x0e\x8b\x7d\x7d\x99\x30\x01\xf1\xea\x1e\x3e\x46"
    "\xf4\xd2\xd9\x80\xaf\x3a\x4b\x2f\xbb\x91\xbb\xb7"
    "\x22\x2d\x6a\x0f\x4e\x6f\x02\x41\x00\xd9\x23\xa7"
    "\x98\x0c\x58\xe1\x5d\xa7\x15\x05\xc6\xd9\x7b\xc5"
    "\x7b\xd3\x01\x8b\x1e\xf1\x2e\x99\xc5\xac\x41\xf1"
    "\x92\x88\xd9\x8e\x50\x86\xf9\x2f\x66\x42\xeb\xf9"
    "\x80\x78\xfa\xc7\xea\x63\x35\x7e\x6f\xc5\x35\x36"
    "\x6b\xa1\x8a\xa3\x49\x97\xbc\xa6\x9b\x5c\x6e\xf1"
    "\x8d\x02\x40\x44\x70\xa0\xbe\x64\xc9\x4e\xd3\x84"
    "\x4d\x45\xaa\x88\x5e\xcf\xe7\x85\xc9\x6e\x43\x87"
    "\xe1\xdb\x20\xe2\x49\x86\xa6\x33\x9f\x8f\x27\xde"
    "\xc5\x98\xde\x19\xd0\xb6\xac\x50\xce\x2e\x35\xad"
    "\x52\xe5\x44\x44\xb5\x73\x87\xfe\x63\xcf\x83\x70"
    "\xb8\x36\xac\x75\x24\xbe\xc7\x02\x41\x00\x87\xd2"
    "\x97\xa8\xb2\x40\x7e\x67\xf8\x75\x5b\xf1\xb0\x64"
    "\x8d\x79\x10\xd9\xec\x4d\xe4\x8b\x43\xc0\xb4\x29"
    "\x63\x94\x47\x69\xde\x6d\x5c\xa0\x4e\x17\xe7\x50"
    "\x77\xf6\xf6\xb5\xd7\x8b\x33\x97\x68\x89\x3d\x90"
    "\x35\x84\x49\xbd\xd0\xb9\xdd\xe2\x31\x4d\x09\x1a"
    "\x94\x99\x02\x41\x00\xc9\x12\xec\x64\xe9\x01\x27"
    "\x10\x6c\xad\xc5\x83\x8a\x26\x39\xe0\x05\xde\xde"
    "\xf9\x1a\x5d\xf6\xcb\xe8\xd2\x9b\x40\xd5\x11\xc8"
    "\x9a\x6d\x29\xb6\x15\x36\x9a\xee\x45\xe2\x51\x14"
    "\xa8\x2d\xab\x57\x86\x80\x87\x0a\x02\xaf\xfa\xda"
    "\x5e\x7d\xfb\x84\xd1\x3a\xe0\xed\x57";
const int priv_key_len = 609;

const char pub_key[] =
    "\x30\x81\x9e\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7"
    "\x0d\x01\x01\x01\x05\x00\x03\x81\x8c\x00\x30\x81"
    "\x88\x02\x81\x80\x6d\x4d\xaf\xf5\x32\x98\xfa\x33"
    "\xf2\x4a\xb0\x50\x27\x6f\x50\x0b\x28\xca\x5f\x6e"
    "\xde\xec\x7b\xae\xeb\xd1\x89\xdf\xcf\x8d\x12\x6c"
    "\x0d\xf2\x32\x65\xb7\x04\xf2\xb8\x76\x67\xe9\x28"
    "\xc3\x12\x6b\x4a\x52\x09\xd6\x61\x9b\x21\x25\x04"
    "\xe0\x9a\xec\xbc\x25\x3f\xfc\x6f\x1a\x98\xa8\x02"
    "\xa8\x2e\x89\x91\x20\xcf\xf0\xd1\x9d\x09\x35\xac"
    "\x95\xe2\xe4\x8e\x5b\x7c\x34\x93\x39\x4f\x33\xbd"
    "\x6e\xe7\xc5\xbb\x2a\x28\x32\x13\x62\x39\x37\x87"
    "\x40\xe7\x59\xf8\x94\xad\xc4\x2e\xaf\x23\xf4\x98"
    "\xcd\x90\x27\x96\x41\xc6\x4a\xcd\x6d\x56\xfd\x5b"
    "\x02\x03\x01\x00\x01";
const int pub_key_len = 161;

//const char *msg = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";
//const int msg_len = 8; 
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
struct akcipher_def {
    struct scatterlist input_list;
    struct scatterlist output_list;
    struct crypto_akcipher *tfm;
    struct akcipher_request *req;
    struct tcrypt_result result;
};

void print_hex(const char *s, unsigned int len)
{ 
  int i;
  for (i=0;i<len;i++)
    printk(KERN_INFO "%02x", (unsigned char)s[i]);
  printk(KERN_INFO "\n");
}

/* Callback function */
void test_akcipher_cb(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS){
       pr_info("Encryption error: inprogress\n");
        return;
    }
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
    encryption_done=1;
}

/* Perform cipher operation */
unsigned int test_akcipher_encdec(struct akcipher_def *ak,
                     int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_akcipher_encrypt(ak->req);
    else
        rc = crypto_akcipher_decrypt(ak->req);

    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &ak->result.completion);
        if (!rc && !ak->result.err) {
            reinit_completion(&ak->result.completion);
            break;
        }
    default:
        
        break;
    }
    pr_info("akcipher encrypt returned with %d result %d\n",
            rc, ak->result.err);
    init_completion(&ak->result.completion);

    return rc;
}

/* Initialize and trigger cipher operation */
static int test_akcipher(void)
{
    
    
    cycles_low=0;
    cycles_high=0;
    cycles_low1=0;
    cycles_high1=0;
    unsigned int out_len_max=0;
    struct akcipher_def ak;
    struct crypto_akcipher *akcipher = NULL;
    struct akcipher_request *req = NULL;
    char *input_buffer = NULL;
    char *output_buffer = NULL;
    char *buf=NULL;
    int ret = -EFAULT;

    akcipher = crypto_alloc_akcipher("rsa", 0, 0);
    if (IS_ERR(akcipher)) {
        pr_info("could not allocate akcipher handle\n");
        return PTR_ERR(akcipher);
    }

    req = akcipher_request_alloc(akcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate akcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_akcipher_cb,
                      &ak.result);
             
	pr_info("Public key size:%u",(unsigned int)sizeof(pub_key));
	pr_info("Private key size:%u",(unsigned int)sizeof(priv_key));

    /* set up private key */
    if (crypto_akcipher_set_priv_key(akcipher, priv_key, priv_key_len)) {
        pr_info("pri key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }  
	
    /* set up public key */
    /*if (crypto_akcipher_set_pub_key(akcipher, pub_key, pub_key_len)) {
        pr_info("pub key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }*/
    
 
    
    /* Input data will be random */
    input_buffer = kmalloc(16, GFP_KERNEL);
    if (!input_buffer) {
        pr_info("could not allocate input_buffer\n");
        goto out;
    }
    //get_random_bytes(input_buffer, 1024);
    memcpy(input_buffer, "AAAAAAAAAAAAAAAA",16);

    out_len_max = crypto_akcipher_maxsize(akcipher);

    output_buffer = kzalloc(out_len_max, GFP_KERNEL);
    if (!output_buffer) {
        pr_info("could not allocate output_buffer\n");
        goto out;
    }
    //get_random_bytes(input_buffer, 16);
    
    ak.tfm = akcipher;
    ak.req = req;
	//pr_info("Scratchpad size:%u",(unsigned int)strlen(scratchpad));
	//print_hex(scratchpad);
    /* We encrypt one block */
    sg_init_one(&ak.input_list, input_buffer, 16);
    sg_init_one(&ak.output_list, output_buffer, out_len_max);
    akcipher_request_set_crypt(req, &ak.input_list, &ak.output_list, 16, out_len_max);
    init_completion(&ak.result.completion);

   	/*buf=sg_virt(&ak.input_list);
	pr_info("Plaintext :");
	print_hex(buf,1024);*/

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
        ret = test_akcipher_encdec(&ak, 1);
	
	while(initial==(value=x86_rdmsr(MSR_PP0_ENERGY_STATUS)));
        asm volatile(   "RDTSCP\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t"
                        "CPUID\n\t": "=r" (cycles_high1), "=r"
        (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");
	start = ( ((uint64_t)cycles_high << 32) | cycles_low );
        end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
	printk(KERN_INFO "rdmsr changes: %llu, time=%llu",(value-initial),end-start);
	raw_local_irq_restore(flags);
	preempt_enable();

	
    if (ret)
        goto out;

    pr_info("Encryption triggered successfully\n");

out:
	/*buf=sg_virt(&ak.output_list);
	pr_info("Ciphertext:");
	print_hex(buf,out_len_max);*/


    if (akcipher)
        crypto_free_akcipher(akcipher);
    if (req)
        akcipher_request_free(req);
    if (input_buffer)
        kfree(input_buffer);
    if (output_buffer)
        kfree(output_buffer);


    return ret;
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

static int __init hello_start(void)
{
  int i=0;
  //for (i=0;i<round;i++)
  //Filltimes(i);
  test_akcipher();
  return;
}

static void __exit hello_end(void)
{
 printk(KERN_INFO "Goodbye Mr.\n");
}

module_init(hello_start);
module_exit(hello_end);


