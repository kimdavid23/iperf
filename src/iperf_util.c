/*
 * iperf, Copyright (c) 2014, 2016, 2017, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */
/* iperf_util.c
 *
 * Iperf utility functions
 *
 */
#include "iperf_config.h"

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include "cjson.h"
#include "iperf.h"
#include "iperf_api.h"
#include "iperf_util.h"

/*
 * Read entropy from /dev/urandom
 * Errors are fatal.
 * Returns 0 on success.
 */
int readentropy(void *out, size_t outsize)
{
    static FILE *frandom;
    static const char rndfile[] = "/dev/urandom";

    if (!outsize) return 0;

    if (frandom == NULL) {
        frandom = fopen(rndfile, "rb");
        if (frandom == NULL) {
            iperf_errexit(NULL, "error - failed to open %s: %s\n",
                          rndfile, strerror(errno));
        }
        setbuf(frandom, NULL);
    }
    if (fread(out, 1, outsize, frandom) != outsize) {
        iperf_errexit(NULL, "error - failed to read %s: %s\n",
                      rndfile,  
                      feof(frandom) ? "EOF" : strerror(errno));
    }
    return 0;
}

int remove_duplicated_lines (char* file1, char* file2, char* outputFilename)
{
    FILE *fileptr1, *fileptr2, *outputFile;

    char line1[100];
    char line2[100];
    char filename1 [100];
    char filename2 [100];
    
	strcpy (filename1, "sorted1.tmp");
	strcpy (filename2, "sorted2.tmp");    

    dup_remove_sort_file (file1, filename1);
    dup_remove_sort_file (file2, filename2);

    fileptr1 = fopen(filename1, "r");
    fileptr2 = fopen(filename2, "r");
    outputFile = fopen(outputFilename, "w");

    if (fileptr1 == NULL || fileptr2 == NULL || outputFile == NULL) {
        return -1;
    }

    fgets(line1, sizeof(line1), fileptr1);
    fgets(line2, sizeof(line2), fileptr2);

    while (!feof(fileptr1) && !feof(fileptr2)) {
        int cmp = atoi(line1) - atoi(line2);

        if (cmp == 0) {
            fgets(line1, sizeof(line1), fileptr1);
            fgets(line2, sizeof(line2), fileptr2);
        } else if (cmp < 0) {
            fprintf(outputFile, "%s", line1);
            fgets(line1, sizeof(line1), fileptr1);
        } else {
            fgets(line2, sizeof(line2), fileptr2);
        }
    }

    while (!feof(fileptr1)) {
        fprintf(outputFile, "%s", line1);        
        fgets(line1, sizeof(line1), fileptr1);        
    }

    fclose(fileptr1);
    fclose(fileptr2);
    fclose(outputFile);

    remove(filename1);
    remove(filename2);

    return 0;
} 

int dup_remove_compare(const void *a, const void *b)
{
    return atoi (*(const char **)a) - atoi (*(const char **)b);
}

void dup_remove_init()
{
    long long init_estimate = (1024 * 1024 * 128);
    dup_remove_strbuf = (char **)malloc(init_estimate * sizeof(char *));
}

void dup_remove_add(char *name, long long* currMaxSize, long long* fileByteCounter, long long *num)
{
    long long incremental_size = (1024 * 1024 * 64);

    if (*num >= *currMaxSize)
    {
        long long temp = *currMaxSize;
        *currMaxSize += incremental_size;
        dup_remove_strbuf = (char **)realloc(dup_remove_strbuf, *currMaxSize * sizeof(char *));
    }
    dup_remove_strbuf[*num] = (char *)malloc(strlen(name) + 1);
    *fileByteCounter += strlen(name) + 1;
    strcpy(dup_remove_strbuf[(*num)++], name);
}

void dup_remove_external_mergesort(char *file__1, char *file__2, char *file__out)
{
    FILE *f1 = fopen(file__1, "r");
    FILE *f2 = fopen(file__2, "r");
    FILE *fileOut = fopen(file__out, "w+");
    bool FILE1_done = false;
    bool FILE2_done = false;
    char tempStr[DUP_REMOVE_MAX_NAME_LEN];
    char tempStr1[DUP_REMOVE_MAX_NAME_LEN] = {'\0'};
    char tempStr2[DUP_REMOVE_MAX_NAME_LEN] = {'\0'};
    int access = DUP_REMOVE_FILE1;
    int asa = 1;
    fscanf(f2, "%s", tempStr2);

    while (!FILE1_done || !FILE2_done)
    {
        char temp[DUP_REMOVE_MAX_NAME_LEN];
        int ff2 = (!FILE2_done && !access) ? fscanf(f2, "%s", tempStr2) : -3;
        int ff1 = (!FILE1_done && access) ? fscanf(f1, "%s", tempStr1) : -3;

        if (ff1 == EOF)
        {
            FILE1_done = true;
            access = DUP_REMOVE_FILE2;
        }
        if (ff2 == EOF)
        {
            FILE2_done = true;
            access = DUP_REMOVE_FILE1;
        }
        if (!FILE1_done && FILE2_done)
        {
            fprintf(fileOut, "%s\n", tempStr1);
            continue;
        }
        if (FILE1_done && !FILE2_done)
        {
            fprintf(fileOut, "%s\n", tempStr2);
            continue;
        }
        if (!FILE1_done && !FILE2_done)
        {
            if (atoi(tempStr1) - atoi(tempStr2) < 0)
            {
                fprintf(fileOut, "%s\n", tempStr1);
                access = DUP_REMOVE_FILE1;
            }
            else
            {
                fprintf(fileOut, "%s\n", tempStr2);
                access = DUP_REMOVE_FILE2;
            }
        }
    }
    fclose(fileOut);
}

long long dup_remove_get_filesize(char *fileName)
{
    struct stat fileStatus;
    if (stat(fileName, &fileStatus) < 0)
        return -1;
    return fileStatus.st_size;
}

void dup_remove_free_resources(long long *num)
{
    for (long long v = 0; v < *num; v++)
        free(dup_remove_strbuf[v]);
    free(dup_remove_strbuf);
    *num = 0;
}

void dup_remove_sort_file_sub(char *fileName, char *outFileName, long long fileSize, long long dup_remove_halfGB)
{
    char tmpname[DUP_REMOVE_MAX_NAME_LEN];
    long long num_of_files = (fileSize + dup_remove_halfGB - 1) / dup_remove_halfGB;
    long long currMaxSize = (1024 * 1024 * 128);
    long long fileByteCounter = 0;
    long long num = 0;

    FILE *f1 = fopen(fileName, "r");
    for (int i = 0; i < num_of_files; i++)
    {
        dup_remove_init();
        while (fscanf(f1, "%s", tmpname) != EOF)
        {
            dup_remove_add(tmpname, &currMaxSize, &fileByteCounter, &num);
            long long tttt = (long long)dup_remove_halfGB * (i + 1);
            if (fileByteCounter >= tttt)
            {
                break;
            }
        }
        char snum[5];
        sprintf(snum, "%d", i);
        char tempFileName[DUP_REMOVE_MAX_NAME_LEN];
        strcpy(tempFileName, outFileName);
        strcat(tempFileName, snum);
        FILE *f2 = fopen(tempFileName, "w+");

        qsort(dup_remove_strbuf, num, sizeof(const char *), dup_remove_compare);

        for (long long i = 0; i < num; i++)
            fprintf(f2, "%s\n", dup_remove_strbuf[i]);
        fclose(f2);
        dup_remove_free_resources(&num);
    }
}

void dup_remove_sort_file (char* fileIn, char* fileOut)
{ 
    long long fileSize = dup_remove_get_filesize(fileIn);
    long long dup_remove_halfGB = 805306368;

    if (fileSize <= dup_remove_halfGB)
    {
        dup_remove_sort_file_sub(fileIn, "OUTPUT_SORTED_FILE_FINAL", fileSize, dup_remove_halfGB);
        rename("OUTPUT_SORTED_FILE_FINAL0", fileOut);
    }
    else if (fileSize > dup_remove_halfGB)
    {
        long long num_of_files = (fileSize + dup_remove_halfGB - 1) / dup_remove_halfGB;
        dup_remove_sort_file_sub(fileIn, "TEMP_SORTED_FILE", fileSize, dup_remove_halfGB);

        while (1)
        {
            long long temp = (num_of_files) / 2;
            long long temp2 = num_of_files;
            num_of_files = (num_of_files + 1) / 2;
            for (int i = 0; i < temp; i++)
            {
                char snum[5];
                sprintf(snum, "%d", 2 * i);
                char snum1[5];
                sprintf(snum1, "%d", 2 * i + 1);
                char tempFileName[DUP_REMOVE_MAX_NAME_LEN];
                char tempFileName1[DUP_REMOVE_MAX_NAME_LEN];
                strcpy(tempFileName, "TEMP_SORTED_FILE");
                strcat(tempFileName, snum);
                strcpy(tempFileName1, "TEMP_SORTED_FILE");
                strcat(tempFileName1, snum1);

                char snum3[5];
                sprintf(snum3, "%d", i);
                char tempFileName2[DUP_REMOVE_MAX_NAME_LEN];
                strcpy(tempFileName2, "TEMP_SORTED_FILE");
                strcat(tempFileName2, snum3);

                dup_remove_external_mergesort(tempFileName, tempFileName1, "TEMP_MERGED_SORTED_FILE");
                remove(tempFileName);
                remove(tempFileName1);
                rename("TEMP_MERGED_SORTED_FILE", tempFileName2);
            }

            if (temp2 % 2)
            {
                char snum[5];
                sprintf(snum, "%lld", temp2 - 1);
                char tempFileName[DUP_REMOVE_MAX_NAME_LEN];
                strcpy(tempFileName, "TEMP_SORTED_FILE");
                strcat(tempFileName, snum);

                char snum1[5];
                sprintf(snum1, "%lld", temp2 / 2);
                char tempFileName1[DUP_REMOVE_MAX_NAME_LEN];
                strcpy(tempFileName1, "TEMP_SORTED_FILE");
                strcat(tempFileName1, snum1);
                rename(tempFileName, tempFileName1);
            }
            if (num_of_files == 1)
            {
                rename("TEMP_SORTED_FILE0", fileOut);
                break;
            }
        }
    }
}


/*
 * Fills buffer with repeating pattern (similar to pattern that used in iperf2)
 */
void fill_with_repeating_pattern(void *out, size_t outsize)
{
    size_t i;
    int counter = 0;
    char *buf = (char *)out;

    if (!outsize) return;

    for (i = 0; i < outsize; i++) {
        buf[i] = (char)('0' + counter);
        if (counter >= 9)
            counter = 0;
        else
            counter++;
    }
}


/* make_cookie
 *
 * Generate and return a cookie string
 *
 * Iperf uses this function to create test "cookies" which
 * server as unique test identifiers. These cookies are also
 * used for the authentication of stream connections.
 * Assumes cookie has size (COOKIE_SIZE + 1) char's.
 */

void make_cookie(const char *cookie)
{
    unsigned char *out = (unsigned char*)cookie;
    size_t pos;
    static const unsigned char rndchars[] = "abcdefghijklmnopqrstuvwxyz234567";

    readentropy(out, COOKIE_SIZE);
    for (pos = 0; pos < (COOKIE_SIZE - 1); pos++) {
        out[pos] = rndchars[out[pos] % (sizeof(rndchars) - 1)];
    }
    out[pos] = '\0';
}


/* is_closed
 *
 * Test if the file descriptor fd is closed.
 *
 * Iperf uses this function to test whether a TCP stream socket
 * is closed, because accepting and denying an invalid connection
 * in iperf_tcp_accept is not considered an error.
 */

int
is_closed(int fd)
{
    struct timeval tv;
    fd_set readset;

    FD_ZERO(&readset);
    FD_SET(fd, &readset);
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    if (select(fd+1, &readset, NULL, NULL, &tv) < 0) {
        if (errno == EBADF)
            return 1;
    }
    return 0;
}


double
timeval_to_double(struct timeval * tv)
{
    double d;

    d = tv->tv_sec + tv->tv_usec / 1000000;

    return d;
}

int
timeval_equals(struct timeval * tv0, struct timeval * tv1)
{
    if ( tv0->tv_sec == tv1->tv_sec && tv0->tv_usec == tv1->tv_usec )
	return 1;
    else
	return 0;
}

double
timeval_diff(struct timeval * tv0, struct timeval * tv1)
{
    double time1, time2;

    time1 = tv0->tv_sec + (tv0->tv_usec / 1000000.0);
    time2 = tv1->tv_sec + (tv1->tv_usec / 1000000.0);

    time1 = time1 - time2;
    if (time1 < 0)
        time1 = -time1;
    return time1;
}

void
cpu_util(double pcpu[3])
{
    static struct iperf_time last;
    static clock_t clast;
    static struct rusage rlast;
    struct iperf_time now, temp_time;
    clock_t ctemp;
    struct rusage rtemp;
    double timediff;
    double userdiff;
    double systemdiff;

    if (pcpu == NULL) {
        iperf_time_now(&last);
        clast = clock();
	getrusage(RUSAGE_SELF, &rlast);
        return;
    }

    iperf_time_now(&now);
    ctemp = clock();
    getrusage(RUSAGE_SELF, &rtemp);

    iperf_time_diff(&now, &last, &temp_time);
    timediff = iperf_time_in_usecs(&temp_time);

    userdiff = ((rtemp.ru_utime.tv_sec * 1000000.0 + rtemp.ru_utime.tv_usec) -
                (rlast.ru_utime.tv_sec * 1000000.0 + rlast.ru_utime.tv_usec));
    systemdiff = ((rtemp.ru_stime.tv_sec * 1000000.0 + rtemp.ru_stime.tv_usec) -
                  (rlast.ru_stime.tv_sec * 1000000.0 + rlast.ru_stime.tv_usec));

    pcpu[0] = (((ctemp - clast) * 1000000.0 / CLOCKS_PER_SEC) / timediff) * 100;
    pcpu[1] = (userdiff / timediff) * 100;
    pcpu[2] = (systemdiff / timediff) * 100;
}

const char *
get_system_info(void)
{
    static char buf[1024];
    struct utsname  uts;

    memset(buf, 0, 1024);
    uname(&uts);

    snprintf(buf, sizeof(buf), "%s %s %s %s %s", uts.sysname, uts.nodename,
	     uts.release, uts.version, uts.machine);

    return buf;
}


const char *
get_optional_features(void)
{
    static char features[1024];
    unsigned int numfeatures = 0;

    snprintf(features, sizeof(features), "Optional features available: ");

#if defined(HAVE_CPU_AFFINITY)
    if (numfeatures > 0) {
	strncat(features, ", ",
		sizeof(features) - strlen(features) - 1);
    }
    strncat(features, "CPU affinity setting",
	sizeof(features) - strlen(features) - 1);
    numfeatures++;
#endif /* HAVE_CPU_AFFINITY */

#if defined(HAVE_FLOWLABEL)
    if (numfeatures > 0) {
	strncat(features, ", ",
		sizeof(features) - strlen(features) - 1);
    }
    strncat(features, "IPv6 flow label",
	sizeof(features) - strlen(features) - 1);
    numfeatures++;
#endif /* HAVE_FLOWLABEL */

#if defined(HAVE_SCTP_H)
    if (numfeatures > 0) {
	strncat(features, ", ",
		sizeof(features) - strlen(features) - 1);
    }
    strncat(features, "SCTP",
	sizeof(features) - strlen(features) - 1);
    numfeatures++;
#endif /* HAVE_SCTP_H */

#if defined(HAVE_TCP_CONGESTION)
    if (numfeatures > 0) {
	strncat(features, ", ",
		sizeof(features) - strlen(features) - 1);
    }
    strncat(features, "TCP congestion algorithm setting",
	sizeof(features) - strlen(features) - 1);
    numfeatures++;
#endif /* HAVE_TCP_CONGESTION */

#if defined(HAVE_SENDFILE)
    if (numfeatures > 0) {
	strncat(features, ", ",
		sizeof(features) - strlen(features) - 1);
    }
    strncat(features, "sendfile / zerocopy",
	sizeof(features) - strlen(features) - 1);
    numfeatures++;
#endif /* HAVE_SENDFILE */

#if defined(HAVE_SO_MAX_PACING_RATE)
    if (numfeatures > 0) {
	strncat(features, ", ",
		sizeof(features) - strlen(features) - 1);
    }
    strncat(features, "socket pacing",
	sizeof(features) - strlen(features) - 1);
    numfeatures++;
#endif /* HAVE_SO_MAX_PACING_RATE */

#if defined(HAVE_SSL)
    if (numfeatures > 0) {
	strncat(features, ", ",
		sizeof(features) - strlen(features) - 1);
    }
    strncat(features, "authentication",
	sizeof(features) - strlen(features) - 1);
    numfeatures++;
#endif /* HAVE_SSL */

#if defined(HAVE_SO_BINDTODEVICE)
    if (numfeatures > 0) {
	strncat(features, ", ",
		sizeof(features) - strlen(features) - 1);
    }
    strncat(features, "bind to device",
	sizeof(features) - strlen(features) - 1);
    numfeatures++;
#endif /* HAVE_SO_BINDTODEVICE */

#if defined(HAVE_DONT_FRAGMENT)
    if (numfeatures > 0) {
	strncat(features, ", ",
		sizeof(features) - strlen(features) - 1);
    }
    strncat(features, "support IPv4 don't fragment",
	sizeof(features) - strlen(features) - 1);
    numfeatures++;
#endif /* HAVE_DONT_FRAGMENT */

    if (numfeatures == 0) {
	strncat(features, "None",
		sizeof(features) - strlen(features) - 1);
    }

    return features;
}

/* Helper routine for building cJSON objects in a printf-like manner.
**
** Sample call:
**   j = iperf_json_printf("foo: %b  bar: %d  bletch: %f  eep: %s", b, i, f, s);
**
** The four formatting characters and the types they expect are:
**   %b  boolean           int
**   %d  integer           int64_t
**   %f  floating point    double
**   %s  string            char *
** If the values you're passing in are not these exact types, you must
** cast them, there is no automatic type coercion/widening here.
**
** The colons mark the end of field names, and blanks are ignored.
**
** This routine is not particularly robust, but it's not part of the API,
** it's just for internal iperf3 use.
*/
cJSON*
iperf_json_printf(const char *format, ...)
{
    cJSON* o;
    va_list argp;
    const char *cp;
    char name[100];
    char* np;
    cJSON* j;

    o = cJSON_CreateObject();
    if (o == NULL)
        return NULL;
    va_start(argp, format);
    np = name;
    for (cp = format; *cp != '\0'; ++cp) {
	switch (*cp) {
	    case ' ':
	    break;
	    case ':':
	    *np = '\0';
	    break;
	    case '%':
	    ++cp;
	    switch (*cp) {
		case 'b':
		j = cJSON_CreateBool(va_arg(argp, int));
		break;
		case 'd':
		j = cJSON_CreateNumber(va_arg(argp, int64_t));
		break;
		case 'f':
		j = cJSON_CreateNumber(va_arg(argp, double));
		break;
		case 's':
		j = cJSON_CreateString(va_arg(argp, char *));
		break;
		default:
		va_end(argp);
		return NULL;
	    }
	    if (j == NULL) {
	    	va_end(argp);
	    	return NULL;
	    }
	    cJSON_AddItemToObject(o, name, j);
	    np = name;
	    break;
	    default:
	    *np++ = *cp;
	    break;
	}
    }
    va_end(argp);
    return o;
}

/* Debugging routine to dump out an fd_set. */
void
iperf_dump_fdset(FILE *fp, const char *str, int nfds, fd_set *fds)
{
    int fd;
    int comma;

    fprintf(fp, "%s: [", str);
    comma = 0;
    for (fd = 0; fd < nfds; ++fd) {
        if (FD_ISSET(fd, fds)) {
	    if (comma)
		fprintf(fp, ", ");
	    fprintf(fp, "%d", fd);
	    comma = 1;
	}
    }
    fprintf(fp, "]\n");
}

/*
 * daemon(3) implementation for systems lacking one.
 * Cobbled together from various daemon(3) implementations,
 * not intended to be general-purpose. */
#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose)
{
    pid_t pid = 0;
    pid_t sid = 0;
    int fd;

    /*
     * Ignore any possible SIGHUP when the parent process exits.
     * Note that the iperf3 server process will eventually install
     * its own signal handler for SIGHUP, so we can be a little
     * sloppy about not restoring the prior value.  This does not
     * generalize.
     */
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) {
	    return -1;
    }
    if (pid > 0) {
	/* Use _exit() to avoid doing atexit() stuff. */
	_exit(0);
    }

    sid = setsid();
    if (sid < 0) {
	return -1;
    }

    /*
     * Fork again to avoid becoming a session leader.
     * This might only matter on old SVr4-derived OSs.
     * Note in particular that glibc and FreeBSD libc
     * only fork once.
     */
    pid = fork();
    if (pid == -1) {
	return -1;
    } else if (pid != 0) {
	_exit(0);
    }

    if (!nochdir) {
	chdir("/");
    }

    if (!noclose && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
	dup2(fd, STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	if (fd > 2) {
	    close(fd);
	}
    }
    return (0);
}
#endif /* HAVE_DAEMON */

/* Compatibility version of getline(3) for systems that don't have it.. */
#ifndef HAVE_GETLINE
/* The following code adopted from NetBSD's getline.c, which is: */

/*-
 * Copyright (c) 2011 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
ssize_t
getdelim(char **buf, size_t *bufsiz, int delimiter, FILE *fp)
{
	char *ptr, *eptr;


	if (*buf == NULL || *bufsiz == 0) {
		*bufsiz = BUFSIZ;
		if ((*buf = malloc(*bufsiz)) == NULL)
			return -1;
	}

	for (ptr = *buf, eptr = *buf + *bufsiz;;) {
		int c = fgetc(fp);
		if (c == -1) {
			if (feof(fp)) {
				ssize_t diff = (ssize_t)(ptr - *buf);
				if (diff != 0) {
					*ptr = '\0';
					return diff;
				}
			}
			return -1;
		}
		*ptr++ = c;
		if (c == delimiter) {
			*ptr = '\0';
			return ptr - *buf;
		}
		if (ptr + 2 >= eptr) {
			char *nbuf;
			size_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			if ((nbuf = realloc(*buf, nbufsiz)) == NULL)
				return -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t
getline(char **buf, size_t *bufsiz, FILE *fp)
{
	return getdelim(buf, bufsiz, '\n', fp);
}

#endif
