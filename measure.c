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
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#define IA32_PERF_STATUS 0x198
//#define ENERGY_MSR MSR_PKG_ENERGY_STATUS
#define ENERGY_MSR MSR_PP0_ENERGY_STATUS
#define round 100000//how many data points to collect
#define repeat_count 20000//in one round, how many times the instruction/code being repeated
//#define round 41000

MODULE_INFO(version, "0.1");
MODULE_AUTHOR("Chen Liu");
MODULE_LICENSE("GPL");

unsigned int cycles_low, cycles_high, cycles_low1, cycles_high1;
unsigned long flags;
uint64_t initial, value=0,middle=0;
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

/*const char priv_key[] =
"\x30\x82\x02\x1F" 
	"\x02\x01\x01" 
	"\x02\x82\x01\x00" 
	"\xDB\x10\x1A\xC2\xA3\xF1\xDC\xFF\x13\x6B\xED\x44\xDF\xF0\x02\x6D"
	"\x13\xC7\x88\xDA\x70\x6B\x54\xF1\xE8\x27\xDC\xC3\x0F\x99\x6A\xFA"
	"\xC6\x67\xFF\x1D\x1E\x3C\x1D\xC1\xB5\x5F\x6C\xC0\xB2\x07\x3A\x6D"
	"\x41\xE4\x25\x99\xAC\xFC\xD2\x0F\x02\xD3\xD1\x54\x06\x1A\x51\x77"
	"\xBD\xB6\xBF\xEA\xA7\x5C\x06\xA9\x5D\x69\x84\x45\xD7\xF5\x05\xBA"
	"\x47\xF0\x1B\xD7\x2B\x24\xEC\xCB\x9B\x1B\x10\x8D\x81\xA0\xBE\xB1"
	"\x8C\x33\xE4\x36\xB8\x43\xEB\x19\x2A\x81\x8D\xDE\x81\x0A\x99\x48"
	"\xB6\xF6\xBC\xCD\x49\x34\x3A\x8F\x26\x94\xE3\x28\x82\x1A\x7C\x8F"
	"\x59\x9F\x45\xE8\x5D\x1A\x45\x76\x04\x56\x05\xA1\xD0\x1B\x8C\x77"
	"\x6D\xAF\x53\xFA\x71\xE2\x67\xE0\x9A\xFE\x03\xA9\x85\xD2\xC9\xAA"
	"\xBA\x2A\xBC\xF4\xA0\x08\xF5\x13\x98\x13\x5D\xF0\xD9\x33\x34\x2A"
	"\x61\xC3\x89\x55\xF0\xAE\x1A\x9C\x22\xEE\x19\x05\x8D\x32\xFE\xEC"
	"\x9C\x84\xBA\xB7\xF9\x6C\x3A\x4F\x07\xFC\x45\xEB\x12\xE5\x7B\xFD"
	"\x55\xE6\x29\x69\xD1\xC2\xE8\xB9\x78\x59\xF6\x79\x10\xC6\x4E\xEB"
	"\x6A\x5E\xB9\x9A\xC7\xC4\x5B\x63\xDA\xA3\x3F\x5E\x92\x7A\x81\x5E"
	"\xD6\xB0\xE2\x62\x8F\x74\x26\xC2\x0C\xD3\x9A\x17\x47\xE6\x8E\xAB"
	"\x02\x03\x01\x00\x01" 
	"\x02\x82\x01\x00"
	"\x52\x41\xF4\xDA\x7B\xB7\x59\x55\xCA\xD4\x2F\x0F\x3A\xCB\xA4\x0D"
	"\x93\x6C\xCC\x9D\xC1\xB2\xFB\xFD\xAE\x40\x31\xAC\x69\x52\x21\x92"
	"\xB3\x27\xDF\xEA\xEE\x2C\x82\xBB\xF7\x40\x32\xD5\x14\xC4\x94\x12"
	"\xEC\xB8\x1F\xCA\x59\xE3\xC1\x78\xF3\x85\xD8\x47\xA5\xD7\x02\x1A"
	"\x65\x79\x97\x0D\x24\xF4\xF0\x67\x6E\x75\x2D\xBF\x10\x3D\xA8\x7D"
	"\xEF\x7F\x60\xE4\xE6\x05\x82\x89\x5D\xDF\xC6\xD2\x6C\x07\x91\x33"
	"\x98\x42\xF0\x02\x00\x25\x38\xC5\x85\x69\x8A\x7D\x2F\x95\x6C\x43"
	"\x9A\xB8\x81\xE2\xD0\x07\x35\xAA\x05\x41\xC9\x1E\xAF\xE4\x04\x3B"
	"\x19\xB8\x73\xA2\xAC\x4B\x1E\x66\x48\xD8\x72\x1F\xAC\xF6\xCB\xBC"
	"\x90\x09\xCA\xEC\x0C\xDC\xF9\x2C\xD7\xEB\xAE\xA3\xA4\x47\xD7\x33"
	"\x2F\x8A\xCA\xBC\x5E\xF0\x77\xE4\x97\x98\x97\xC7\x10\x91\x7D\x2A"
	"\xA6\xFF\x46\x83\x97\xDE\xE9\xE2\x17\x03\x06\x14\xE2\xD7\xB1\x1D"
	"\x77\xAF\x51\x27\x5B\x5E\x69\xB8\x81\xE6\x11\xC5\x43\x23\x81\x04"
	"\x62\xFF\xE9\x46\xB8\xD8\x44\xDB\xA5\xCC\x31\x54\x34\xCE\x3E\x82"
	"\xD6\xBF\x7A\x0B\x64\x21\x6D\x88\x7E\x5B\x45\x12\x1E\x63\x8D\x49"
	"\xA7\x1D\xD9\x1E\x06\xCD\xE8\xBA\x2C\x8C\x69\x32\xEA\xBE\x60\x71"
	"\x02\x01\x00"
	"\x02\x01\x00"
	"\x02\x01\x00"
	"\x02\x01\x00"
	"\x02\x01\x00"; 
const int priv_key_len = 547;*/

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
#pragma GCC push_options
#pragma GCC optimize ("O0")
void inline x86_100_add(uint32_t src, uint32_t dst)
{	
	__asm__("add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		"add %1, %0\n\t"
		:"+r"(dst)
		:"r"(src)
		:
	);

}


void inline x86_100_ror(uint32_t u, size_t r)
{	
	__asm__("rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		"rorl %%cl, %0\n\t"
		:"+r"(u)
		:"c"(r)
	);
//	printk(KERN_ERR "Value=%x",u);
}
void inline x86_100_mul(unsigned int foo, unsigned int bar)
{
	//int foo=10, bar=15;
	int upper;
	__asm__("mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		"mul %%ebx\n\t"
		:"=a"(foo),"=d"(upper)
		:"a"(foo),"b"(bar)
		:"cc"
		);
}
#pragma GCC pop_options
void inline x86_100_nop(void)
{
	asm volatile (
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
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

struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};


struct file *filp;

struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void file_close(struct file *file) 
{
    filp_close(file, NULL);
}

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

void test_skcipher_cb(struct crypto_async_request *req, int error)
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
//    pr_info("akcipher encrypt returned with %d result %d\n", rc, ak->result.err);
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
	int i;
	unsigned int extra=0;
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
    input_buffer = kmalloc(64, GFP_KERNEL);
    if (!input_buffer) {
        pr_info("could not allocate input_buffer\n");
        goto out;
    }
    //get_random_bytes(input_buffer, 1024);
    memcpy(input_buffer, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",64);

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
	
	initial=x86_rdmsr(ENERGY_MSR);
	while(initial==(value=x86_rdmsr(ENERGY_MSR)));
	initial=value;
	asm volatile (  "CPUID\n\t"
                        "RDTSC\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r"
        (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");

        /* encrypt data */
	for (i=0;i<1000;i++)
        ret = test_akcipher_encdec(&ak, 1);
	//msleep(2000);
	
	middle=x86_rdmsr(ENERGY_MSR);	
	while(middle==(value=x86_rdmsr(ENERGY_MSR))){
		extra++;	
	}
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
	 printk(KERN_ERR "time=%llu, extra rdmsr performed=%d\n",end-start,extra);
	
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

#pragma GCC push_options
#pragma GCC optimize ("O0")
/* Initialize and trigger cipher operation */
static uint64_t test_cipher(char* buf)
{
    uint64_t start,end,initial,middle, value=0,time_span, freq_init,freq_final;
    unsigned int extra=0;
    char output_content[100]={};
    int i;
    cycles_low=0;
    cycles_high=0;
    cycles_low1=0;
    cycles_high1=0;
    struct crypto_cipher *cipher = NULL;
    //char buf[16]="AAAAAAAAAAAAAAAA";
    //char buf[16]="DDDDDDDDDDDDDDDD";
    char key[16]="BBBBBBBBBBBBBBBB";
    //char key[16]="CCCCCCCCCCCCCCCC";
    //char key[16]="\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    char buf_cipher[16]="XXXXXXXXXXXXXXXX";

    int ret = -EFAULT;

    cipher = crypto_alloc_cipher("aes-asm", 0, 0);
    if (IS_ERR(cipher)) {
        pr_info("could not allocate cipher handle\n");
        goto out;
    }

    /* AES 128 with random key */
   // get_random_bytes(&key, 16);
    if (crypto_cipher_setkey(cipher, key, 16)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

	//pr_info("Plaintext size:%u",(unsigned int)strlen(buf));
	//print_hex(buf,(unsigned int)strlen(buf));
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
	
	initial=x86_rdmsr(ENERGY_MSR);
	while(initial==(value=x86_rdmsr(ENERGY_MSR)));
	initial=value;

	freq_init=(x86_rdmsr(IA32_PERF_STATUS)>>8)&0x7F;

	asm volatile (  "CPUID\n\t"
                        "RDTSC\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r"
        (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");

        /* encrypt data */

	for (i=0;i<repeat_count;i++)
        	crypto_cipher_encrypt_one(cipher,buf_cipher,buf);
	

	middle=x86_rdmsr(ENERGY_MSR);	
	while(middle==(value=x86_rdmsr(ENERGY_MSR))){
		extra++;	
	}
        asm volatile(   "RDTSCP\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t"
                        "CPUID\n\t": "=r" (cycles_high1), "=r"
        (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");

	freq_final=(x86_rdmsr(IA32_PERF_STATUS)>>8)&0x7F;

	start = ( ((uint64_t)cycles_high << 32) | cycles_low );
        end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );


	printk(KERN_ERR "rdmsr changes: %llu, value: %llu, initial: %llu",(value-initial),value,initial);
	raw_local_irq_restore(flags);
	preempt_enable();

	time_span=end-start;
 	printk(KERN_ERR "time=%llu, extra rdmsr performed=%d\n",time_span,extra);

out:
    if (cipher)
        crypto_free_cipher(cipher);
   /* if (buf)measure-aes.c
        kfree(buf);*/
    // while(!encryption_done);
	//pr_info("Ciphertext:");
	//print_hex(buf_cipher);
	if (freq_init==freq_final){
		do_div(time_span, (unsigned int)(value-initial));
		sprintf(output_content, "%llu %llu %llu %llu\n",(value-initial),(end-start),time_span,freq_init);
		kernel_write(filp, output_content, (unsigned int)strlen(output_content), &filp->f_pos);
		return 0;
	}
	else return 1;
}



unsigned int inline measure(unsigned int op1, unsigned int op2, unsigned int count) {
	unsigned long flags;
	uint64_t start,end,initial,middle, value=0,time_span;
	uint64_t volt_init, volt_final,freq_init,freq_final;
	cycles_low=cycles_high=cycles_low1=cycles_high1=0;
	volatile int i = 0;
	unsigned int extra=0;
	char output_content[100]={};
	//output_content = kmalloc(64, GFP_KERNEL);

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
	
	initial=x86_rdmsr(ENERGY_MSR);
	while(initial==(value=x86_rdmsr(ENERGY_MSR)));
	initial=value;

	//volt_init=(x86_rdmsr(IA32_PERF_STATUS)>>32)&0xFF;

	/*voltage before*/
	freq_init=(x86_rdmsr(IA32_PERF_STATUS)>>8)&0x7F;
	asm volatile (  "CPUID\n\t"
                        "RDTSC\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r"
        (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");
/*------------------------------------ Your code --------------------------------------*/
	  for (i=0;i<count;i++){
	    //x86_rdmsr(MSR_PP0_ENERGY_STATUS);
	    //x86_100_nop();
		//x86_100_mul(op1,op2);
			//x86_100_ror(0x12345678,678);
			x86_100_add(op1,op2);

//			x86_100_mul(1,1);
			//x86_100_ror(0xaaaaaaaa,1);
		

	}
/*--------------------------------------------------------------------------------------*/
	middle=x86_rdmsr(ENERGY_MSR);	
	while(middle==(value=x86_rdmsr(ENERGY_MSR))){
		extra++;	
	}
	//volt_final=(x86_rdmsr(IA32_PERF_STATUS)>>32)&0xFF;
	
        asm volatile(   "RDTSCP\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t"
                        "CPUID\n\t": "=r" (cycles_high1), "=r"
        (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");
	/*voltage after*/
	freq_final=(x86_rdmsr(IA32_PERF_STATUS)>>8)&0x7F;

	printk(KERN_ERR "rdmsr changes: %llu, value: %llu, initial: %llu",(value-initial),value,initial);
	
	
        raw_local_irq_restore(flags);
        preempt_enable();


	start = ( ((uint64_t)cycles_high << 32) | cycles_low );
	end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
	time_span=end-start;

 	printk(KERN_ERR "time=%llu, extra rdmsr performed=%d\n",time_span,extra);
	
	if (freq_init==freq_final){
		do_div(time_span, (unsigned int)(value-initial));
		sprintf(output_content, "%llu %llu %llu %llu\n",(value-initial),(end-start),time_span,freq_init);
		kernel_write(filp, output_content, (unsigned int)strlen(output_content), &filp->f_pos);
		return 0;
	}
	else
		return 1;
}

static int __init hello_start(void)
{
  	int i=0;
	unsigned int op1,op2;
	char buf[16]="AAAAAAAAAAAAAAAA";
	filp=filp_open("/home/ipas/measure/result/aes_static_20000", O_WRONLY|O_CREAT, 0644);

	//printk(KERN_ERR "rand1=%u rand2=%u\n",op1,op2);
  	for (i=0;i<round;i++){
  	//Filltimes(i);
	//get_random_bytes(&op1, sizeof(op1));
	//get_random_bytes(&op2, sizeof(op2));
	//get_random_bytes(buf, sizeof(buf));
  	//i-=measure(999,999,repeat_count);
	i-=test_cipher(buf);
		printk(KERN_ERR "round=%u\n",i);
	}
	//printk(KERN_ERR "add input 2\n");
 	//measure(0,1000000);
	

  	//test_akcipher();
	file_close(filp);
  	return;
}

static void __exit hello_end(void)
{
 printk(KERN_INFO "Goodbye Mr.\n");
}

module_init(hello_start);
module_exit(hello_end);


