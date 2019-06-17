/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <iostream>
#include <fstream>
#include <time.h>

#define IA32_PERF_STATUS 0x198
#define PP0_ENERGY_MSR 0x639

using namespace std;
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadatecall_sgx_cpuida.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

uint64_t rdmsr_on_cpu(uint32_t reg, int cpu)
{
	uint64_t data;
	int fd;
	char msr_file_name[64];
	unsigned int bits;
	unsigned int highbit = 63, lowbit = 0;

	sprintf(msr_file_name, "/dev/cpu/%d/msr", cpu);
	fd = open(msr_file_name, O_RDONLY);


	if (pread(fd, &data, sizeof data, reg) != sizeof data) {
		if (errno == EIO) {
			fprintf(stderr, "rdmsr: CPU %d cannot read "
				"MSR 0x%08"PRIx32"\n",
				cpu, reg);
			exit(4);
		} else {
			perror("rdmsr: pread");
			exit(127);
		}
	}

	close(fd);


	bits = highbit - lowbit + 1;
	if (bits < 64) {
		/* Show only part of register */
		data >>= lowbit;
		data &= (1ULL << bits) - 1;
	}

	return data;

}
/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    //printf("Enclave is created successfully.\n");
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


unsigned int generate_key(unsigned int hw){
	if (hw>32)
		return 0;
	unsigned int key=0;
	for (int i=0;i<hw;i++){
		unsigned int bit=(1<<(rand()%32));
		while ((bit&key))
			bit=(1<<(rand()%32));	
		key=key^bit;
	}
	return key;
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    
	unsigned long flags;
	uint64_t start,end,initial,middle, value=0,time_span;
	uint64_t freq_init,freq_final;
	unsigned int cycles_low, cycles_high, cycles_low1, cycles_high1;
	
	volatile int i = 0, j=0,k=0;
	unsigned int extra=0;
	

    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

	ofstream outfile;
	outfile.open("no-overflow-2.txt",ofstream::app|ofstream::out);
	srand(time(NULL));


    for (i=0;i<1000;i++){
	//if ((i%1000)==0)
		printf ("round=%u\n",i);
	
	start=end=initial=middle=value=0;
	freq_init=freq_final=0;
	//unsigned int d1=2080374784;//d1 HW=5
	//unsigned int d2=33554431;//d2 HW=25
	//unsigned int d3=559240; //d3 HW=5
	//unsigned int d4=0xFFFFFF80; //d4 HW=25
	char output_content[100]={};
	extra=0;
	cycles_low=cycles_high=cycles_low1=cycles_high1=0;

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

        //preempt_disable();
        //raw_local_irq_save(flags);
	
	unsigned int d=generate_key(5); // secret key
	
	unsigned int hw_d=0,temp_d=d;
	for (j=0;j<32;j++)
		hw_d+=((temp_d>>j)&1); 

	initial=rdmsr_on_cpu(PP0_ENERGY_MSR,0);
	//printf("Hello\n");
	while(initial==(value=rdmsr_on_cpu(PP0_ENERGY_MSR,0)));
	initial=value;
	
	//volt_init=(x86_rdmsr(IA32_PERF_STATUS)>>32)&0xFF;

	/*voltage before*/
	freq_init=(rdmsr_on_cpu(IA32_PERF_STATUS,0)>>8)&0x7F;
	asm volatile (  "CPUID\n\t"
                        "RDTSC\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t": "=r" (cycles_high), "=r"
        (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");
	
/*------------------------------------ Your code --------------------------------------*/
	test_fun(global_eid);
/*--------------------------------------------------------------------------------------*/
	middle=rdmsr_on_cpu(PP0_ENERGY_MSR,0);	
	while(middle==(value=rdmsr_on_cpu(PP0_ENERGY_MSR,0))){
		extra++;	
	}
	//volt_final=(x86_rdmsr(IA32_PERF_STATUS)>>32)&0xFF;
	
        asm volatile(   "RDTSCP\n\t"
                        "mov %%edx, %0\n\t"
                        "mov %%eax, %1\n\t"
                        "CPUID\n\t": "=r" (cycles_high1), "=r"
        (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");
	/*voltage after*/
	freq_final=(rdmsr_on_cpu(IA32_PERF_STATUS,0)>>8)&0x7F;
	
	//printf("rdmsr changes: %llu, value: %llu, initial: %llu\n",(value-initial),value,initial);
	
	
        //raw_local_irq_restore(flags);
        //preempt_enable();


	start = ( ((uint64_t)cycles_high << 32) | cycles_low );
	end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
	time_span=end-start;

 	//printf("time=%llu, extra rdmsr performed=%d\n",time_span,extra);
	if (freq_final==36){
		if (freq_init==freq_final){
		
		//sprintf(output_content,"%u %u %llu %llu\n",hw_d,d, (value-initial),time_span);
		sprintf(output_content,"%llu	%llu\n",(value-initial), time_span);
		outfile<<output_content;
		//sprintf(output_content, "%llu %llu %llu %llu\n",(value-initial),(end-start),time_span,freq_init);

		}
	}	
	else break;
	}
	
	outfile.close();
    

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    //for (int i=0;i<10000;i++);
    
    return i;
}

