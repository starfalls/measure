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
 * OF THIS SOFTWARE,4 EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <stdlib.h>
#include <sgx_trts.h>
#define d_hw5_1 2080374784;
#define d_hw5_2 559240; 2
#define d_hw5_3 277119488; 
#define d_hw5_4 334237; 
#define d_hw5_5 1073783297; 
#define d_hw10_1 1079040266;
#define d_hw10_2 3294701648;
#define d_hw10_3 292047012;
#define d_hw10_4 538707245;
#define d_hw10_5 470116512;
#define d_hw15_1 2844966406;
#define d_hw15_2 1148358377;
#define d_hw15_3 1029014603;
#define d_hw15_4 3561094704;
#define d_hw15_5 2911536331;
#define d_hw25_1 335454431;
#define d_hw25_2 4294967168; 
#define d_hw25_3 2549608437; 
#define d_hw25_4 3891784663; 
#define d_hw25_5 3883920253;
#define mult1 1
#define mult2 2
#define mult3 3
#define mult4 0xFFFFFFFF 	
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

unsigned int generate_key(unsigned int hw){
	if (hw>32)
		return 0;
	unsigned int key=0;
	for (int i=0;i<hw;i++){
		uint32_t val;
		sgx_read_rand((unsigned char *)&val,4);
		unsigned int bit=(1<<(val%32));
		while ((bit&key)){
			sgx_read_rand((unsigned char *)&val,4);
			bit=(1<<(val%32));	
		}
		key=key^bit;
	}
	return key;
}

#pragma GCC push_options
#pragma GCC optimize ("O0")
void test_fun() {
	//unsigned long long n=6557;//79*83
	//unsigned long long c=1234567890;//0x499602D2
	//unsigned long long i=0,j=0,k=0;
	//unsigned long long r=1, r_dummy=1;
	unsigned long long r=1;
	//for (int i=0;i<1000000;i++){
	//	r=(r*mult1)%mult2;
	//}
	for (int i=0;i<100000;i++){
		r=1;
		for (int j=0;j<20;j++)	
			r=r*mult2;
	}

	//srand(time(NULL));
	//d=generate_key(25); // secret key
	//unsigned long long d=d_hw5_1;
	//unsigned long long r_init=r, c_init=c, d_init=d, r_dummy_init=r_dummy;
	//printf("d=%4u\n",d);
/*------------------------------------ Your code --------------------------------------*/
	//printk(KERN_ERR "r=%u, c=%u, d=%u\n",r,c,d);
	//for (i=0;i<750000;i++){
	/*for (i=0;i<1000000;i++){
		r=r_init;
		c=c_init;
		r_dummy=r_dummy_init;
		d=d_init;        
	for (j=0;j<32;j++){
	  if (d&1){
	    r=(r*c)%n;
	  }
	  else {
	    r_dummy=(r_dummy*c)%n;
	  }
	  c=(c*c)%n;
	  d=d>>1;
	}
	}*/
/*--------------------------------------------------------------------------------------*/
	//printf("after: r=%u, r_dummy=%u, c=%u, d=%u\n",r,r_dummy,c,d);

}

#pragma GCC pop_options
