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

void print_hex(const char *s)
{ 
  int i;
  for (i=0;i<16;i++)
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
    struct akcipher_def ak;
    struct crypto_akcipher *akcipher = NULL;
    struct akcipher_request *req = NULL;
    char *input_buffer = NULL;
    char *output_buffer = NULL;
    char priv_key[]="	MIIEowIBAAKCAQEArTBrmOdIylgP5m1td2eQYdHzbeUmIdp+QFpeLvyCWD7CRaON \
			kQegr3Nin0MgDkd40nlU4tU7WgnUpyTYPEsCKxwjfWCHC0rST05KOtZvRt/NShnv \
			YyYbPkcYQXItzdbpRt3pM2qqq5nrFLd7R0uoW6/1Q+ixtZxVw6LVSE+qEMDnAdk3 \
			9f5uWFu17XA4+3crE+ptkziZirhn7FQjE+u7EBOAlrJQ5ZDTvok5mVmLxs8RwGKl \
			cCJzbX/fKLlM7mCByOrSd464HIJsHQq/eLResFA1L0gAHMKAFxiVJUbGcLkN/x1t \
			6QLqMwr+y4EAxVRNJaDFS8fG3Nbeo87HR4vXIQIDAQABAoIBAQCgdFHbkbxgq4Hf \
			rNZUYADmgAuWb00K5FE/8fl8crmYZFy9BDBug7CdnLtsblZOpG0OIxdAKOoaGy2H \
			xZ0JDz1tD17aFApJrgJ3M0OWi4EBGuwpkSm2pGFtK5UPXWeOY2QxIfuihVqmLa4c \
			vXlbrn7Go5kKV5X9emADJuOPYS9g4LF105R5rSFQC7iIMeIYzMa8GGLgL1FUUvvw \
			y0d+rrUAy3Rws3b8zb05UKELMr1rFNgqyprXsUlp3OYILFs0Fua8Qw/5rKNWJj2c \
			Lo6/P5DBEELj+Agkx2y4aBpW9kZcBBXdascmPPVzYVOrfoZFY7fBdi3U0YIsP5Nk \
			Xqu6SlqBAoGBANTMKmkEdoZLGhxqQuQN/29o5YucSUamh82Pg+MkMWXWhVcoj725 \
			dQskI20vGM0sSmrGI5G8Fs6EuyHZLt3JGtGPPuLAIJMaiSxSZGff7IWm+vfxL6mh \
			fXuKX8yQVbGUVS89r2pB+VzYzmmkq5QW4giWOXy689H2YUWGXq5oS+XpAoGBANBZ \
			qwVcbi7yWBHTnLs1xaaRAj0+QWg1xbIRKTo8fMTjnDAs7XGIws32MZMxfsMu4rXw \
			LME9yeIqfVE6UJCnd+q3UvTZSKqmX7zm1rK+Y1EAfdMemJgzTyFfV+zwHErGz0ZB \
			3H5XCdcVjR/t2LbT/vmQzbLARYU2uosKn/e2M0x5AoGARgSXv85UIYP8p3TfZaKl \
			dccSIIngInsRHDYos0hpaJTZcwBJq6emN3BAp+BjTL9SDSf89CrrZjCOUmjf3uIZ \
			DPMRQhLtpPmKQScrGnK3pJJ46bRWdn5Ih6nUM78aM0AXd1/YpCHpJv+/i0s/mY6d \
			+S1U5RGuwFtNTk8UQFbZAmECgYAI0nMqY/KKbFqMTrCJQMqgte0pWLR+TCCV3KIp \
			RBxoXdbkN1LKhubwv6bzu5nJe/e/im7qs8oTmIb75IM6zMyIFMEfev/XsfnFzuRy \
			Zxtfd6zcPqRpdWq5WAcqEjSweeCW8fz7IIZbJB94paKSg0F9ocMD+Z43+MxHTOjf \
			HUjoyQKBgD1nfQayjhR+/0vx/lvOrduLHNPUslcQtJEKdju9phYcs0iuW0jMLtSZ \
			5+YU3fRfT6NC47RVMXV7OJQhPTCjHU9sw/9NobZvSy2apR+O6lmmET9F27JsoBi2 \
			QdaCOuv2FvLlOfcs62Su5ureYu8VpW1iMe8hv2y5KIxjElAANBJo";
    char pub_key[]="	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArTBrmOdIylgP5m1td2eQ \
			YdHzbeUmIdp+QFpeLvyCWD7CRaONkQegr3Nin0MgDkd40nlU4tU7WgnUpyTYPEsC \
			KxwjfWCHC0rST05KOtZvRt/NShnvYyYbPkcYQXItzdbpRt3pM2qqq5nrFLd7R0uo \
			W6/1Q+ixtZxVw6LVSE+qEMDnAdk39f5uWFu17XA4+3crE+ptkziZirhn7FQjE+u7 \
			EBOAlrJQ5ZDTvok5mVmLxs8RwGKlcCJzbX/fKLlM7mCByOrSd464HIJsHQq/eLRe \
			sFA1L0gAHMKAFxiVJUbGcLkN/x1t6QLqMwr+y4EAxVRNJaDFS8fG3Nbeo87HR4vX \
			IQIDAQAB";
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
             
	pr_info("Public key size:%u",(unsigned int)strlen(pub_key));
	pr_info("Private key size:%u",(unsigned int)strlen(priv_key));
	
    if (crypto_akcipher_set_pub_key(akcipher, pub_key, (unsigned int)strlen(pub_key))) {
        pr_info("pub key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }
    
    if (crypto_akcipher_set_priv_key(akcipher, priv_key, (unsigned int)strlen(priv_key))) {
        pr_info("pri key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }   
    
    /* Input data will be random */
    input_buffer = kmalloc(16, GFP_KERNEL);
//pr_info("Scratchpad size before get random:%u",(unsigned int)strlen(scratchpad));
    if (!input_buffer) {
        pr_info("could not allocate input_buffer\n");
        goto out;
    }
    get_random_bytes(input_buffer, 16);
    //scratchpad="1234567812345678";

    output_buffer = kmalloc(1000, GFP_KERNEL);
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
    sg_init_one(&ak.output_list, output_buffer, 1000);
    akcipher_request_set_crypt(req, &ak.input_list, &ak.output_list, 16, 1000);
    init_completion(&ak.result.completion);
    //buf=sg_virt(&ak.sg);
	//pr_info("Plaintext size %u:", (unsigned int)strlen(buf));
	//print_hex(buf);

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
	asm volatile (  "CPUID\n\t"
                        "RDTSC\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r"
        (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");

        /* encrypt data */
        ret = test_akcipher_encdec(&ak, 1);

        asm volatile(   "RDTSCP\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t"
                        "CPUID\n\t": "=r" (cycles_high1), "=r"
        (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");
	start = ( ((uint64_t)cycles_high << 32) | cycles_low );
        end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
	printk(KERN_INFO "rdmsr changes: %llu, time=%llu",(x86_rdmsr(MSR_PP0_ENERGY_STATUS)-value),end-start);
	raw_local_irq_restore(flags);
	preempt_enable();

	
    if (ret)
        goto out;

    pr_info("Encryption triggered successfully\n");

out:
    if (akcipher)
        crypto_free_akcipher(akcipher);
    if (req)
        akcipher_request_free(req);
    if (pub_key)
        kfree(pub_key);
    if (priv_key)
        kfree(priv_key);
    if (input_buffer)
        kfree(input_buffer);
    if (output_buffer)
        kfree(output_buffer);

	//pr_info("Ciphertext:");
	//print_hex(buf);
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


