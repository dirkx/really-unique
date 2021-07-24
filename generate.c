/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#include <openssl/conf.h>
#include <openssl/ossl_typ.h>

#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <openssl/bnerr.h>
#include <openssl/err.h>

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include "uthash/uthash.h"

int verbose = 0;
int noopenssl;
int noseed;

void usage(char * prog) {
	fprintf(stderr,"Syntax %s [-r /dev/random] N\n" \
"\n" \
"	-r dev  Random device; designed for the Infinite Noise TRNG. Can be repeated.\n" \
"	-S      Do not seed with a counter and previous value.\n" \
"	-O      Do not fall back to OpenSSL rand if no device is specified.\n" \
"\n" \
"	N       number of 256 bits keys to output\n"\
"\n",prog);
	exit(1);
}

#define assertOrBail(x) { if (!(x)) { BIO_printf(err, "Fatal Error (%s:%d)\n",__FILE__,__LINE__); ERR_print_errors(err); exit(1); }; }

void pexit(char *msg, ...) {
	va_list(ap);
	if (msg && *msg) {
        	va_start(ap, msg);
		vfprintf(stderr, msg, ap);
		if (msg[strlen(msg)-1] >= 32)  
			perror(": ");
	} else {
		fprintf(stderr,"Unknown error, aborting.");
	};
	exit(1);
};

// Linked list of random devices. Designed for nCipher or Inifnity RNG hardware.
//
typedef struct rdev {
	char * fname;
	int fd;
	struct rdev *nxt;
} rdev_t;

rdev_t * rdevs = NULL;

// Keep a hashtable - to guarantee no duplicates whatsoever
// in our tests.
//
typedef struct mdentry { 
	unsigned char md[SHA256_DIGEST_LENGTH]; 
	UT_hash_handle hh;
} mdentry_t;

void add_rnddevice(char * fname ) {
	rdev_t * p = rdevs;
	if (!(rdevs = malloc(sizeof(rdev_t))))
		pexit("No memory for rdev");
	rdevs->nxt = p;
	rdevs->fname = optarg;
	if ((rdevs->fd = open(fname, O_RDONLY | O_NONBLOCK))<0)
		pexit("Could not open %s", optarg);
};

int main(int argc, char ** argv) {
	extern char *optarg;
	extern int optind, optopt;
	char c;

    	while ((c = getopt(argc, argv, "vOSr:")) != -1) {
	 	switch(c) {
        	case 'r': add_rnddevice(optarg);
			break;
        	case 'v':
			verbose++;
			break;
        	case 'S':
			noseed = 1;
			break;
        	case 'O':
			noopenssl = 1;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}
	if (argc - optind < 1)
		usage(argv[0]);
        argc -= optind;
        argv += optind;;

	size_t N = strtoull(argv[0],NULL,10);

	if (rdevs && noopenssl)
		fprintf(stderr,"Ignoring -O flag (as a device is used instead already).\n");

	if (rdevs == NULL && noopenssl && noseed && N != 1)
		pexit("No randomness - so endless hash collisions. Not going to try.\n");

	// used as a rolling buffer - mixed into the SHA256
	//
	unsigned char rolling_md[SHA256_DIGEST_LENGTH];
	bzero(rolling_md,sizeof(rolling_md));

	mdentry_t *e, * entries = NULL;
	size_t cols = 0;

	for(unsigned long long i = 0; i < N; i++) {
		if (verbose) 
			fprintf(stderr,"Generating %llu\n", i+1);
	
		do {	
			SHA256_CTX ctx;
			if (1 != SHA256_Init(&ctx)) 
				pexit("SHA256 init error\n");

			if (!noseed) {
			   	// Seed with the counter and the previous SHA256 as a precaution.
				if (1 != SHA256_Update(&ctx,&i,sizeof(i))) 
					pexit("SHA256 error\n");
				if (1 != SHA256_Update(&ctx,rolling_md,sizeof(rolling_md))) 
					pexit("SHA256 error\n");
			};
	
			for(rdev_t * p = rdevs; p; p=p->nxt) {
				unsigned char buff[SHA256_DIGEST_LENGTH];
				int len = read(p->fd, buff, sizeof(buff));
				if (len < 1 && errno != EAGAIN && errno != EINTR && errno != EWOULDBLOCK)
					pexit("Error reading rnd device %s", p->fname);
				if ((len>0) && (1 != SHA256_Update(&ctx,buff,len))) 
					pexit("SHA256 error\n");
			};
			if (rdevs == NULL && !noopenssl) {
				unsigned char buff[SHA256_DIGEST_LENGTH];
				if (1 != RAND_bytes(buff,sizeof(buff))) pexit("OpenSSL rand error\n");
				if (1 != SHA256_Update(&ctx,buff,sizeof(buff))) pexit("SHA256 error\n");
			};

			SHA256_Final(rolling_md, &ctx);
			HASH_FIND(hh, entries, rolling_md, SHA256_DIGEST_LENGTH, e);
			if (e) cols++;
		} while(e);

		mdentry_t *entry;
		if (!(entry= malloc(sizeof(mdentry_t))))
			pexit("Out of memory on entry");

		bcopy(rolling_md,entry->md,SHA256_DIGEST_LENGTH);
		HASH_ADD(hh, entries, md, SHA256_DIGEST_LENGTH, entry);

		write(STDOUT_FILENO, entry->md, sizeof(entry->md));			
	};
	if (cols)
		fprintf(stderr,"Hash collission (%zu in total) - very odd.\n",cols);
	exit(0);
};
