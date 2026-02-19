/* Declarations for FTP support.
   Copyright (C) 1996-2011, 2015, 2018-2022 Free Software Foundation,
   Inc.

This file is part of GNU Wget.

GNU Wget is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

GNU Wget is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Wget.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this program, or any covered work, by linking or
combining it with the OpenSSL project's OpenSSL library (or a
modified version of that library), containing parts covered by the
terms of the OpenSSL or SSLeay licenses, the Free Software Foundation
grants you additional permission to convey the resulting work.
Corresponding Source for a non-source form of such a combination
shall include the source code for the parts of OpenSSL used as well
as that of the covered work.  */

#ifndef FTP_H
#define FTP_H

#include <stdio.h>
#include <stdbool.h>

#include "hash.h"
#include "host.h"
#include "url.h"

/* System types. */
enum stype
{
  ST_UNIX,
  ST_VMS,
  ST_WINNT,
  ST_MACOS,
  ST_OS400,
  ST_OTHER
};

/* Extensions of the ST_UNIX */
enum ustype
{
  UST_TYPE_L8,
  UST_MULTINET,
  UST_OTHER
};

#ifdef HAVE_SSL
/* Data channel protection levels (to be used with PBSZ) */
enum prot_level
{
  PROT_CLEAR = 'C',
  PROT_SAFE = 'S',
  PROT_CONFIDENTIAL = 'E',
  PROT_PRIVATE = 'P'
};
#endif

int write_control_message_send (char *buf, int bufsize, FILE *warc_conv_tmp);
int write_control_message_recv (char *buf, int bufsize, FILE *warc_conv_tmp);
int write_control_message_event (char *buf, int bufsize, FILE *warc_conv_tmp);

uerr_t ftp_response (int, char **, FILE *warc_conv_tmp);
uerr_t ftp_greeting (int, FILE *warc_conv_tmp);
uerr_t ftp_login (int, const char *, const char *, FILE *warc_conv_tmp);
uerr_t ftp_port (int, int *, FILE *warc_conv_tmp);
uerr_t ftp_pasv (int, ip_address *, int *, FILE *warc_conv_tmp);
#ifdef HAVE_SSL
uerr_t ftp_auth (int, enum url_scheme, FILE *warc_conv_tmp);
uerr_t ftp_pbsz (int, int, FILE *warc_conv_tmp);
uerr_t ftp_prot (int, enum prot_level, FILE *warc_conv_tmp);
#endif
#ifdef ENABLE_IPV6
uerr_t ftp_lprt (int, int *, FILE *warc_conv_tmp);
uerr_t ftp_lpsv (int, ip_address *, int *, FILE *warc_conv_tmp);
uerr_t ftp_eprt (int, int *, FILE *warc_conv_tmp);
uerr_t ftp_epsv (int, ip_address *, int *, FILE *warc_conv_tmp);
#endif
uerr_t ftp_type (int, int, FILE *warc_conv_tmp);
uerr_t ftp_cwd (int, const char *, FILE *warc_conv_tmp);
uerr_t ftp_retr (int, const char *, FILE *warc_conv_tmp);
uerr_t ftp_rest (int, wgint, FILE *warc_conv_tmp);
uerr_t ftp_list (int, const char *, bool, bool, bool *, FILE *warc_conv_tmp);
uerr_t ftp_syst (int, enum stype *, enum ustype *, FILE *warc_conv_tmp);
uerr_t ftp_feat (int, FILE *warc_conv_tmp);
uerr_t ftp_quit (int, FILE *warc_conv_tmp);
uerr_t ftp_help (int, FILE *warc_conv_tmp);
uerr_t ftp_stat (int, FILE *warc_conv_tmp);
uerr_t ftp_noop (int, FILE *warc_conv_tmp);
uerr_t ftp_pwd (int, char **, FILE *warc_conv_tmp);
uerr_t ftp_size (int, const char *, wgint *, FILE *warc_conv_tmp);

#ifdef ENABLE_OPIE
const char *skey_response (int, const char *, const char *);
#endif

struct url;
struct luahooks_url;

/* File types.  */
enum ftype
{
  FT_PLAINFILE,
  FT_DIRECTORY,
  FT_SYMLINK,
  FT_UNKNOWN
};


/* Globbing (used by ftp_retrieve_glob).  */
enum
{
  GLOB_GLOBALL, GLOB_GETALL, GLOB_GETONE
};

/* Used by to test if time parsed includes hours and minutes. */
enum parsetype
{
  TT_HOUR_MIN, TT_DAY
};

/* Reason for rejecting a FTP URL. */
typedef enum
{
  FTP_RR_SUCCESS,
  FTP_RR_NOTACCEPTABLE,
  FTP_RR_INSECURENAME,
  FTP_RR_INVALID,
  FTP_RR_REGEX,
  FTP_RR_GLOB,
  FTP_RR_LUAHOOK,
  FTP_RR_BLACKLIST
} ftp_reject_reason;


/* Information about one filename in a linked list.  */
struct fileinfo
{
  enum ftype type;          /* file type */
  char *name;               /* file name */
  wgint size;               /* file size */
  long tstamp;              /* time-stamp */
  enum parsetype ptype;     /* time parsing */
  int perms;                /* file permissions */
  char *linkto;             /* link to which file points */
  struct fileinfo *prev;    /* previous... */
  struct fileinfo *next;    /* ...and next structure. */
};

/* Tracking some information from http_stat in http.h for the Lua hooks. */
struct http_stat_partial
{
  wgint len;                    /* received length */
  wgint contlen;                /* expected length */
  wgint restval;                /* the restart value */
  int res;                      /* the result of last read */
  char *rderrmsg;               /* error message from read error */
  int statcode;                 /* status code */
  char *message;                /* status message */
  wgint rd_size;                /* amount of data read from socket */
  double dltime;                /* time it took to download the data */
  char *local_file;             /* local file name. */
};

/* The WARC control conversation metadata record requires context
   information coming from the resource record holding the FTP data.
   The information is stored in this struct. */
struct warc_context
{
  FILE *ccon_fp;                /* WARC conversation file pointer */
  FILE *fp;                     /* WARC resource data file pointer */
  FILE *html_fp;                /* HTML directory file pointer */
  bool written_resource;        /* if the FTP data was written to fp */
  int is_list;                  /* if a LIST command will be or was run to retrieve the content */
  off_t number;                 /* the number of the conversation record in the session */
  ip_address ip_addr;           /* IP address of the control connection */
  ip_address ip_addr_data;      /* IP address of the data connection */
  char concurrent_to_uuid[48];  /* WARC record ID of the metadata conversation */
  char record_id_uuid[48];      /* WARC record ID of the resource */
  char origin_id_uuid[48];      /* WARC record ID of the first record of the session */
  struct url *url;              /* current URL */
  enum secure_protocol csock_protocol;
  const char *csock_cipher_name;
  enum secure_protocol dtsock_protocol;
  const char *dtsock_cipher_name;

  struct fileinfo *fileinfo;

  struct http_stat_partial *hstatp;
};

/* Commands for FTP functions.  */
enum wget_ftp_command
{
  DO_LOGIN      = 0x0001,   /* Connect and login to the server.  */
  DO_CWD        = 0x0002,   /* Change current directory.  */
  DO_RETR       = 0x0004,   /* Retrieve the file.  */
  DO_LIST       = 0x0008,   /* Retrieve the directory list.  */
  LEAVE_PENDING = 0x0010    /* Do not close the socket.  */
};

enum wget_ftp_fstatus
{
  NOTHING       = 0x0000,   /* Nothing done yet.  */
  ON_YOUR_OWN   = 0x0001,   /* The ftp_loop_internal sets the
                               defaults.  */
  DONE_CWD      = 0x0002,   /* The current working directory is
                               correct.  */

  /* 2013-10-17 Andrea Urbani (matfanjol)
     For more information about the following entries, please,
     look at ftp.c, function getftp, text "__LIST_A_EXPLANATION__". */
  AVOID_LIST_A  = 0x0004,   /* It tells us if during this
                               session we have to avoid the use
                               of "LIST -a".*/
  AVOID_LIST    = 0x0008,   /* It tells us if during this
                               session we have to avoid to use
                               "LIST". */
  LIST_AFTER_LIST_A_CHECK_DONE  = 0x0010,
                            /* It tells us if we have already
                               checked "LIST" after the first
                               "LIST -a" to handle the case of
                               file/folders named "-a". */
  DATA_CHANNEL_SECURITY = 0x0020 /* Establish a secure data channel */
};

struct fileinfo *ftp_parse_ls (const char *, const enum stype);
struct fileinfo *ftp_parse_ls_fp (FILE *, const enum stype);
void freefileinfo(struct fileinfo *);
uerr_t ftp_loop (struct url *, struct url *, char **, int *, struct url *,
                 bool, bool, struct hash_table *, struct luahooks_url **);

uerr_t ftp_index (const char *, struct url *, struct fileinfo *, struct warc_context *);

char ftp_process_type (const char *);


#endif /* FTP_H */
