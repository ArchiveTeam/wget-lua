/* File Transfer Protocol support.
   Copyright (C) 1996-2011, 2014-2015, 2018-2022 Free Software
   Foundation, Inc.

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

#include "wget.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include "utils.h"
#include "url.h"
#include "retr.h"
#include "ftp.h"
#include "ssl.h"
#include "connect.h"
#include "host.h"
#include "netrc.h"
#include "convert.h"            /* for downloaded_file */
#include "recur.h"              /* for INFINITE_RECURSION */
#include "warc.h"
#include "luahooks.h"
#include "hash.h"
#include "c-strcase.h"
#ifdef ENABLE_XATTR
#include "xattr.h"
#endif

#ifdef __VMS
# include "vms.h"
#endif /* def __VMS */


/* File where the "ls -al" listing will be saved.  */
#ifdef MSDOS
#define LIST_FILENAME "_listing"
#else
#define LIST_FILENAME ".listing"
#endif

typedef struct
{
  int st;                       /* connection status */
  int cmd;                      /* command code */
  int csock;                    /* control connection socket */
  double dltime;                /* time of the download in msecs */
  enum stype rs;                /* remote system reported by ftp server */
  enum ustype rsu;              /* when rs is ST_UNIX, here there are more details */
  char *id;                     /* initial directory */
  char *target;                 /* target file name */
  struct url *proxy;            /* FTWK-style proxy */
} ccon;


/* Look for regexp "( *[0-9]+ *byte" (literal parenthesis) anywhere in
   the string S, and return the number converted to wgint, if found, 0
   otherwise.  */
static wgint
ftp_expected_bytes (const char *s)
{
  wgint res;

  while (1)
    {
      while (*s && *s != '(')
        ++s;
      if (!*s)
        return 0;
      ++s;                      /* skip the '(' */
      res = str_to_wgint (s, (char **) &s, 10);
      if (!*s)
        return 0;
      while (*s && c_isspace (*s))
        ++s;
      if (!*s)
        return 0;
      if (c_tolower (*s) != 'b')
        continue;
      if (c_strncasecmp (s, "byte", 4))
        continue;
      else
        break;
    }
  return res;
}

#ifdef ENABLE_IPV6
/*
 * This function sets up a passive data connection with the FTP server.
 * It is merely a wrapper around ftp_epsv, ftp_lpsv and ftp_pasv.
 */
static uerr_t
ftp_do_pasv (int csock, ip_address *addr, int *port, FILE *warc_conv_tmp)
{
  uerr_t err;

  /* We need to determine the address family and need to call
     getpeername, so while we're at it, store the address to ADDR.
     ftp_pasv and ftp_lpsv can simply override it.  */
  if (!socket_ip_address (csock, addr, ENDPOINT_PEER))
    abort ();

  /* If our control connection is over IPv6, then we first try EPSV and then
   * LPSV if the former is not supported. If the control connection is over
   * IPv4, we simply issue the good old PASV request. */
  switch (addr->family)
    {
    case AF_INET:
      if (!opt.server_response)
        logputs (LOG_VERBOSE, "==> PASV ... ");
      err = ftp_pasv (csock, addr, port, warc_conv_tmp);
      break;
    case AF_INET6:
      if (!opt.server_response)
        logputs (LOG_VERBOSE, "==> EPSV ... ");
      err = ftp_epsv (csock, addr, port, warc_conv_tmp);

      /* If EPSV is not supported try LPSV */
      if (err == FTPNOPASV)
        {
          if (!opt.server_response)
            logputs (LOG_VERBOSE, "==> LPSV ... ");
          err = ftp_lpsv (csock, addr, port, warc_conv_tmp);
        }
      break;
    default:
      abort ();
    }

  return err;
}

/*
 * This function sets up an active data connection with the FTP server.
 * It is merely a wrapper around ftp_eprt, ftp_lprt and ftp_port.
 */
static uerr_t
ftp_do_port (int csock, int *local_sock, FILE *warc_conv_tmp)
{
  uerr_t err;
  ip_address cip;

  if (!socket_ip_address (csock, &cip, ENDPOINT_PEER))
    abort ();

  /* If our control connection is over IPv6, then we first try EPRT and then
   * LPRT if the former is not supported. If the control connection is over
   * IPv4, we simply issue the good old PORT request. */
  switch (cip.family)
    {
    case AF_INET:
      if (!opt.server_response)
        logputs (LOG_VERBOSE, "==> PORT ... ");
      err = ftp_port (csock, local_sock, warc_conv_tmp);
      break;
    case AF_INET6:
      if (!opt.server_response)
        logputs (LOG_VERBOSE, "==> EPRT ... ");
      err = ftp_eprt (csock, local_sock, warc_conv_tmp);

      /* If EPRT is not supported try LPRT */
      if (err == FTPPORTERR)
        {
          if (!opt.server_response)
            logputs (LOG_VERBOSE, "==> LPRT ... ");
          err = ftp_lprt (csock, local_sock, warc_conv_tmp);
        }
      break;
    default:
      abort ();
    }
  return err;
}
#else

static uerr_t
ftp_do_pasv (int csock, ip_address *addr, int *port, FILE *warc_conv_tmp)
{
  if (!opt.server_response)
    logputs (LOG_VERBOSE, "==> PASV ... ");
  return ftp_pasv (csock, addr, port, warc_conv_tmp);
}

static uerr_t
ftp_do_port (int csock, int *local_sock, FILE *warc_conv_tmp)
{
  if (!opt.server_response)
    logputs (LOG_VERBOSE, "==> PORT ... ");
  return ftp_port (csock, local_sock, warc_conv_tmp);
}
#endif

static void
print_length (wgint size, wgint start, bool authoritative)
{
  logprintf (LOG_VERBOSE, _("Length: %s"), number_to_static_string (size));
  if (size >= 1024)
    logprintf (LOG_VERBOSE, " (%s)", human_readable (size, 10, 1));
  if (start > 0)
    {
      if (size - start >= 1024)
        logprintf (LOG_VERBOSE, _(", %s (%s) remaining"),
                   number_to_static_string (size - start),
                   human_readable (size - start, 10, 1));
      else
        logprintf (LOG_VERBOSE, _(", %s remaining"),
                   number_to_static_string (size - start));
    }
  logputs (LOG_VERBOSE, !authoritative ? _(" (unauthoritative)\n") : "\n");
}

static uerr_t ftp_get_listing (struct url *, struct url *, ccon *, struct fileinfo **, struct warc_context *, struct hash_table *, struct luahooks_url **);

/* Write an event message to the WARC control connection fp using host
   and port. */
int
write_control_message_host_port (char *str, const char *host, int port,
                                 char *extra, FILE *warc_conv_tmp)
{
  uerr_t err = RETROK;

  if (warc_conv_tmp == NULL)
    return err;

  char port_str[6], *msg;

  if (extra == NULL)
    extra = "";

  port = sprintf (port_str, "%d", port);
  msg = concat_strings (str, " ", host, ":", port_str, extra, "\r\n", (char *) 0);

  if (write_control_message_event (msg, -1, warc_conv_tmp) < 0)
    err = WARC_TMP_FWRITEERR;

  xfree (msg);

  return err;
}

/* Get the ip and port using a socket, it is also determined if this is
   an IPv6 address or not. */
uerr_t
socket_to_string (char **ip_s, char **port_s, bool *is_ipv6, int sock)
{
  struct sockaddr_storage addr;
  char port_str[6], ip_str[64], s;
  socklen_t len = sizeof (addr);

  if (getpeername (sock, (struct sockaddr*)&addr, &len) < 0
      || getnameinfo((struct sockaddr *)&addr, len, ip_str, sizeof(ip_str),
              port_str, sizeof(port_str), NI_NUMERICHOST | NI_NUMERICSERV) != 0)
    return CONSOCKERR;

  *ip_s = xstrdup (ip_str);
  *port_s = xstrdup (port_str);

  if (addr.ss_family == AF_INET)
    *is_ipv6 = false;
  else if (addr.ss_family == AF_INET6)
    *is_ipv6 = true;
  else
    abort();

  return RETROK;
}

/* Write a control message to the WARC control connection fp. */
int
write_control_message_sock (char *str, char **ip_s, int *port_d, int sock,
                            char *extra, FILE *warc_conv_tmp)
{
  uerr_t err = RETROK;

  if (warc_conv_tmp == NULL)
    return err;

  uerr_t err_tmp;
  char *ip_str, *port_str, *msg;
  bool is_ipv6 = true;

  if (extra == NULL)
    extra = "";

  err_tmp = socket_to_string (&ip_str, &port_str, &is_ipv6, sock);
  if (err_tmp != RETROK)
    return err_tmp;

  if (ip_s != NULL)
    *ip_s = xstrdup (ip_str);
  if (port_d != NULL)
    *port_d = atoi (port_str);

  msg = concat_strings (str, " ", is_ipv6 ? "[" : "", ip_str, is_ipv6 ? "]" : "",
                        ":", port_str, extra, "\r\n", (char *) 0);

  if (write_control_message_event (msg, -1, warc_conv_tmp) < 0)
    err = WARC_TMP_FWRITEERR;

  xfree (msg);
  xfree (ip_str);
  xfree (port_str);

  return err;
}

/* Close a control connection and/or data connection, and write a an
   event message about the closing of the socket to the control connection
   filepointer. */
static uerr_t
close_sock (int csock, int dtsock, ccon *con, FILE *warc_conv_tmp,
            uerr_t err_orig)
{
  uerr_t err = FTPOK;
  char *ip_s;
  int port;

  /* If the error is one that signals a problem, a string of the message
     if created to print to the control conversation record. */
  bool bad_error = (err_orig != FTPOK && err_orig != RETRFINISHED && err_orig != RETROK);
  char *err_message = NULL;
  if (bad_error)
    err_message = concat_strings ("An error occurred: ", uerr_to_string (err_orig), "\r\n", (char *) 0);

  /* Close the data connection if given. */
  if (dtsock != 0)
    {
      if (bad_error
          && write_control_message_event (err_message, -1, warc_conv_tmp) < 0)
        err = WARC_TMP_FWRITEERR;

      /* An event message is written on closing and on having closed the
         socket. This looks redundant, but is being written now to support
         this message in the future in case of any checks on closing the
         connection in the future. */
      err = write_control_message_sock ("Closing data connection to", &ip_s,
                                        &port, dtsock, NULL, warc_conv_tmp);
      fd_close (dtsock);
      if (err != RETROK)
        return err;
      err = write_control_message_host_port ("Closed data connection to", ip_s,
                                             port, NULL, warc_conv_tmp);
      if (err != RETROK)
        return err;

      if (warc_conv_tmp != NULL)
        {
          xfree (ip_s);
          ip_s = NULL;
        }
    }

  /* Close the control connection if given. */
  if (csock != 0)
    {
      /* If the error is not printed before, print it now. */
      if (!bad_error)
        {
          if (opt.warc_filename != NULL)
            {
              if (!opt.server_response)
                logprintf (LOG_VERBOSE, "==> QUIT ... ");
              err = ftp_quit (csock, warc_conv_tmp);
            }
        }
      else if (dtsock == 0
               && write_control_message_event (err_message, -1, warc_conv_tmp) < 0)
        err = WARC_TMP_FWRITEERR;

      err = write_control_message_sock ("Closing control connection to", &ip_s,
                                        &port, csock, NULL, warc_conv_tmp);
      fd_close (csock);
      con->csock = -1;
      if (err != RETROK)
        return err;
      err = write_control_message_host_port ("Closed control connection to",
                                             ip_s, port, NULL, warc_conv_tmp);
      if (err != RETROK)
        return err;

      if (warc_conv_tmp != NULL)
        xfree (ip_s);
    }

  if (err_message != NULL)
    xfree (err_message);

  return err_orig;
}

static uerr_t
get_ftp_greeting (int csock, ccon *con, FILE *warc_conv_tmp)
{
  uerr_t err = 0;

  /* Get the server's greeting */
  err = ftp_greeting (csock, warc_conv_tmp);
  if (err != FTPOK)
    {
      logputs (LOG_NOTQUIET, "Error in server response. Closing.\n");
      err = close_sock (csock, 0, con, warc_conv_tmp, err);
    }

  return err;
}

/* Writes a metadata WARC record for the control conversation. Since the
   state of the control connection depends on the previous metadata
   records with commands, the ID of the first record in the session is
   mentioned in the WARC headers, and the number in the session of the
   current record. */
static uerr_t
write_warc_cconv (struct warc_context *warc_context, ccon *con)
{
  uerr_t err_tmp;
  const char *warc_protocol[3] = {NULL};
  char *url;

  /* If the control connection is still open, mention it is kept. */
  if (con->csock != -1)
    {
      err_tmp = write_control_message_sock ("Kept control connection to", NULL,
                                            NULL, con->csock, NULL,
                                            warc_context->ccon_fp);
      if (err_tmp != RETROK)
        return err_tmp;
    }

  /* Copy the WARC record ID of the current control conversation record
     as the origin record ID if not set yet. */
  if (warc_context->number == 0)
    {
      strncpy (warc_context->origin_id_uuid, warc_context->concurrent_to_uuid,
               sizeof (warc_context->origin_id_uuid));
      /* The count of the metadata records is increased from 0 to 1,
         the starting value. */
      warc_context->number++;
    }

  warc_protocol[0] = "ftp";
  if (warc_context->csock_protocol != secure_protocol_none)
    warc_protocol[1] = warc_protocol_to_string (warc_context->csock_protocol);
  else
    warc_protocol[1] = NULL;

  url = url_string (warc_context->url, URL_AUTH_SHOW);

  /* Write the current control conversation record. */
  if (warc_context->concurrent_to_uuid == NULL
      || fflush (warc_context->ccon_fp) != 0
      || (warc_context->is_list == 1
          && url[strlen(url)-1] != '/')
      || !warc_write_metadata_record (warc_context->concurrent_to_uuid,
                                      url, NULL,
                                      NULL, &warc_context->ip_addr,
                                      "text/x-ftp-control-conversation",
                                      warc_context->ccon_fp, -1,
                                      warc_protocol, warc_context->csock_cipher_name,
                                      warc_context->origin_id_uuid,
                                      warc_context->number))
    return WARC_ERR;

  xfree (url);

  /* The control conversation file pointer is already closed after writing. */
  warc_context->ccon_fp = NULL;
  warc_context->number++;

  return RETROK;
}

/* Rotate the current control conversation record. This writes the record
   and opens a new file for the next record. */
static uerr_t
rotate_warc_cconv (struct warc_context *warc_context, ccon *con)
{
  uerr_t err;

  err = write_warc_cconv (warc_context, con);
  if (err != RETROK)
    return err;

  // clear_warc_context (warc_context);
  warc_context->ccon_fp = warc_tempfile ();
  if (warc_context->ccon_fp == NULL)
    return WARC_TMP_FOPENERR;

  return RETROK;
}

/* Write the WARC resource record holding the contents of the data
   retrieved in the context of the current log of the control conversation.

   The data in the resource record can be either a file or a directory
   listing. A file is written with Content-Type text/plain, while a
   directory is written with Content-Type application/octet-stream.

   In case of a directory listing, an HTML-ized version is written as well if
   available. This is stored as conversion record referring to the resource
   record. */
static uerr_t
write_warc_resource (struct warc_context *warc_context, ccon *con)
{
  const char *warc_protocol[3] = {NULL};
  char *url;

  /* Check if anything was actually written. */
  if (!warc_context->written_resource)
    {
      fclose (warc_context->fp);
      return RETROK;
    }

  warc_protocol[0] = "ftp";
  if (warc_context->dtsock_protocol != secure_protocol_none)
    warc_protocol[1] = warc_protocol_to_string (warc_context->dtsock_protocol);
  else
    warc_protocol[1] = NULL;

  url = url_string (warc_context->url, URL_AUTH_SHOW);

  bool write_to_warc = luahooks_write_to_warc_ftp (warc_context->url, warc_context->hstatp);

  /* Write the resource record. Here, the IP of the data connection is
     used, as this is where the data in the resource record came in from.
     The metadata control conversation record will have the IP address
     connected to the control conversation only.

     In most cases, the control and data connection IPs will be the same. */
  if (fflush (warc_context->fp) != 0
      || (warc_context->is_list == 1
          && url[strlen(url)-1] != '/')
      || (write_to_warc
          && !warc_write_resource_record (warc_context->record_id_uuid,
                                      url, NULL,
                                      warc_context->concurrent_to_uuid,
                                      &warc_context->ip_addr_data,
                                      warc_context->is_list == 1 ? "text/plain" : "application/octet-stream",
                                      warc_context->fp, 0,
                                      warc_protocol, warc_context->dtsock_cipher_name)))
    return WARC_ERR;

  /* The record was not written, so the file was not closed. */
  if (!write_to_warc)
    fclose (warc_context->fp);

  warc_context->dtsock_protocol = secure_protocol_none;
  warc_context->dtsock_cipher_name = NULL;
  warc_context->fp = NULL;
  memset (&warc_context->ip_addr_data, 0, sizeof (ip_address));

  /* Write a HTML-ized directory listing if available. */
  if (warc_context->html_fp != NULL)
    {
      if (!warc_context->is_list)
        return WARC_ERR;

      if (fflush (warc_context->html_fp) != 0
          || (write_to_warc
              && !warc_write_conversion_record (NULL, url, NULL,
                                    warc_context->record_id_uuid, "text/html",
                                    warc_context->html_fp)))
        return WARC_TMP_FWRITEERR;

      if (!write_to_warc)
        fclose (warc_context->html_fp);

      warc_context->html_fp = NULL;
    }

  xfree (url);

  return RETROK;
}

/* Write the current WARC resource record, and prepare for a new record. */
static uerr_t
rotate_warc_resource (struct warc_context *warc_context, ccon *con)
{
  if (warc_context->fp != NULL)
    {
      if (write_warc_resource (warc_context, con) != RETROK)
        return WARC_ERR;

      warc_context->fp = warc_tempfile ();
      if (warc_context->fp == NULL)
        return WARC_TMP_FOPENERR;
    }

  return RETROK;
}

/* Write the URL for the WARC records. URL u->url can not be used here due
   to how the LIST command is used, see below. */
static uerr_t
warc_context_set_url (struct warc_context *warc_context, ccon *con,
                      struct url *u)
{
  char *tmp_url_file;

  /* No URL should be set yet. */
  if (warc_context->url != NULL)
    return WARC_ERR;

  /* Keep track on if this is list command or not. */
  if (con->cmd & DO_LIST)
    warc_context->is_list = 1;
  else
    warc_context->is_list = 0;

  warc_context->url = url_copy (u);

  /* Wget attempts to retrieve the directory of an FTP file
     in certain situations, while keeping u->url equal to
     the original input. We can therefore not use u->url for
     the WARC records of this retrieved directory.

     The LIST command is used when flag DO_LIST is set. If
     DO_LIST is set, directory u->dir is downloaded, while
     u->file is not used. If u->file is set though, this
     filename will be reflected in u->url, which would be
     the wrong URL for the WARC records. In that case a new
     URL needs to be built for the WARC records. */
  if (warc_context->is_list == 1)
    {
      /* The RETR and LIST commands should not be both performed.
         This should not be set, an extra check on this. */
      if (con->cmd & DO_RETR)
        return WARC_ERR;

      url_set_file (warc_context->url, "");
    }

  return RETROK;
}

/* Rotate the current WARC context. The WARC records are written out and
   a new warc_context is prepared. The URL is stored at this point as
   well. */
static uerr_t
rotate_warc_context (struct warc_context *warc_context, ccon *con, struct url *u,
                     bool no_reset_context)
{
  uerr_t err;

  /* Write new UUIDs for the resource and metadata records. These are
     written right before writing the WARC records. */
  warc_uuid_str (warc_context->record_id_uuid,
                 sizeof (warc_context->record_id_uuid));
  warc_uuid_str (warc_context->concurrent_to_uuid,
                 sizeof (warc_context->concurrent_to_uuid));

  /* Write out the WARC records. */
  err = rotate_warc_resource (warc_context, con);
  if (err != RETROK)
    return err;

  err = rotate_warc_cconv (warc_context, con);
  if (err != RETROK)
    return err;

  if (!no_reset_context)
    {
      /* Reset data. The file pointers are already rotated right after writing
         the WARC records. */
      warc_context->is_list = -1;
      warc_context->written_resource = false;
      if (warc_context->hstatp != NULL)
        {
          xfree (warc_context->hstatp->rderrmsg);
          xfree (warc_context->hstatp->message);
          xfree (warc_context->hstatp);
        }
      warc_context->hstatp = xnew0 (struct http_stat_partial);
      warc_context->fileinfo = NULL;
      url_free (warc_context->url);
      warc_context->url = NULL;
      memset (&warc_context->ip_addr, 0, sizeof (ip_address));

      /* Set the new URL. */
      err = warc_context_set_url (warc_context, con, u);
      if (err != RETROK)
        return err;
    }

  /* The UUIDs were only required for writing the previous records.
     The warc_context->origin_id_uuid should not be cleared as this holds
     the UUID of the first control conversation record. */
  xzero (warc_context->record_id_uuid);
  xzero (warc_context->concurrent_to_uuid);

  return RETROK;
}

/* Create the warc_context. Create file pointers, and set the URL. */
static uerr_t
create_warc_context (struct warc_context *warc_context, ccon *con, struct url *u)
{
  uerr_t err;

  xzero (*warc_context);

  warc_context->fp = warc_tempfile ();
  warc_context->ccon_fp = warc_tempfile ();
  if (warc_context->fp == NULL || warc_context->ccon_fp == NULL)
    return WARC_TMP_FOPENERR;

  warc_context->is_list = -1;
  warc_context->written_resource = false;

  warc_context->csock_protocol = secure_protocol_none;
  warc_context->csock_cipher_name = NULL;
  warc_context->dtsock_protocol = secure_protocol_none;
  warc_context->dtsock_cipher_name = NULL;

  warc_context->hstatp = xnew0 (struct http_stat_partial);

  err = warc_context_set_url (warc_context, con, u);
  if (err != RETROK)
    return err;

  return RETROK;
}

#ifdef HAVE_SSL
/* Write an event message about actions on an SSL handshake or session.
   This could also be a session continued by another connection. */
static uerr_t
write_control_message_ssl_connection (char *initial, int csock, struct url *u,
                                      FILE *warc_conv_tmp)
{
  uerr_t err = RETROK;

  if (warc_conv_tmp == NULL)
    return err;

  char *tmp1 = concat_strings (initial, " SSL handshake on", (char *) 0);
  char *tmp2 = concat_strings (" for host ", u->host, (char *) 0);

  err = write_control_message_sock (tmp1, NULL, NULL, csock, tmp2, warc_conv_tmp);

  xfree (tmp1);
  xfree (tmp2);

  return err;
}

static uerr_t
init_control_ssl_connection (int csock, struct url *u, bool *using_control_security,
                             ccon *con, FILE *warc_conv_tmp,
                             struct warc_context *warc_context)
{
  bool using_security = false;
  uerr_t err;

  /* If '--ftps-implicit' was passed, perform the SSL handshake directly,
   * and do not send an AUTH command.
   * Otherwise send an AUTH sequence before login,
   * and perform the SSL handshake if accepted by server.
   */
  if (!opt.ftps_implicit && !opt.server_response)
    logputs (LOG_VERBOSE, "==> AUTH TLS ... ");
  if (opt.ftps_implicit || ftp_auth (csock, SCHEME_FTPS, warc_conv_tmp) == FTPOK)
    {
      if (write_control_message_ssl_connection ("Performing", csock, u,
                                                warc_conv_tmp) != RETROK)
        return WARC_TMP_FWRITEERR;
      if (!ssl_connect_wget (csock, u->host, NULL))
        {
          if (write_control_message_ssl_connection ("Failed to perform", csock,
                                                    u, warc_conv_tmp) != RETROK)
            return WARC_TMP_FWRITEERR;
          return close_sock (csock, 0, con, warc_conv_tmp, CONSSLERR);
        }

      if (opt.warc_filename != NULL)
        {
          err = rotate_warc_context (warc_context, con, u, true);
          if (err != RETROK)
            return err;
        }

      err = write_control_message_sock ("Reusing control connection to", NULL,
                                            NULL, csock, NULL, warc_context->ccon_fp);
      if (err != RETROK)
        return err;

      if (opt.warc_filename != NULL)
        {
          warc_context->csock_protocol = ssl_get_protocol (csock);
          if (warc_context->csock_protocol == secure_protocol_none)
            return close_sock (csock, 0, con, warc_conv_tmp, CONSSLERR);
          warc_context->csock_cipher_name = ssl_get_cipher_name (csock);
        }

      if (write_control_message_ssl_connection ("Performed", csock, u,
                                                warc_conv_tmp) != RETROK)
        return WARC_TMP_FWRITEERR;

      if (!ssl_check_certificate (csock, u->host))
        {
          return close_sock (csock, 0, con, warc_conv_tmp, VERIFCERTERR);
        }

      if (!opt.ftps_implicit && !opt.server_response)
        logputs (LOG_VERBOSE, " done.\n");

      /* If implicit FTPS was requested, we act as "normal" FTP, but over SSL.
       * We're not using RFC 2228 commands.
       */
      using_security = true;
    }
  else
    {
      /* The server does not support 'AUTH TLS'.
       * Check if --ftps-fallback-to-ftp was passed. */
      if (opt.ftps_fallback_to_ftp)
        {
          logputs (LOG_NOTQUIET, "Server does not support AUTH TLS. Falling back to FTP.\n");
          using_security = false;
        }
      else
        {
          return close_sock (csock, 0, con, warc_conv_tmp, FTPNOAUTH);
        }
    }

  *using_control_security = using_security;
  return NOCONERROR;
}
#endif

/* Retrieves a file with denoted parameters through opening an FTP
   connection to the server.  It always closes the data connection,
   and closes the control connection in case of error.  If the data
   is to be written to a WARC, the control conversation will be written
   to ccon_fp in warc_context.  */
static uerr_t
getftp (struct url *u, struct url *original_url,
        wgint passed_expected_bytes, wgint *qtyread,
        wgint restval, ccon *con, int count, wgint *last_expected_bytes,
        struct warc_context *warc_context)
{
  int csock, dtsock, local_sock, res;
  uerr_t err = RETROK;          /* appease the compiler */
  uerr_t err_tmp;
  FILE *fp = NULL;
  char *respline, *tms, *received_msg, rd_size_s[30], *tmp;
  const char *user, *passwd, *tmrate;
  int cmd = con->cmd;
  wgint expected_bytes = 0;
  bool got_expected_bytes = false;
  bool rest_failed = false;
  int flags;
  wgint rd_size, previous_rd_size = 0;
  char type_char;
  bool try_again;
  bool list_a_used = false;
#ifdef HAVE_SSL
  enum prot_level prot = (opt.ftps_clear_data_connection ? PROT_CLEAR : PROT_PRIVATE);
  /* these variables tell whether the target server
   * accepts the security extensions (RFC 2228) or not,
   * and whether we're actually using any of them
   * (encryption at the control connection only,
   * or both at control and data connections) */
  bool using_control_security = false, using_data_security = false;
#endif

  assert (con != NULL);
  assert (con->target != NULL);

  /* Debug-check of the sanity of the request by making sure that LIST
     and RETR are never both requested (since we can handle only one
     at a time.  */
  assert (!((cmd & DO_LIST) && (cmd & DO_RETR)));
  /* Make sure that at least *something* is requested.  */
  assert ((cmd & (DO_LIST | DO_CWD | DO_RETR | DO_LOGIN)) != 0);
  *qtyread = restval;

  /* Find the username with priority */
  if (u->user)
    user = u->user;
  else if (opt.user && (opt.use_askpass || opt.ask_passwd))
    user = opt.user;
  else if (opt.ftp_user)
    user = opt.ftp_user;
  else if (opt.user)
    user = opt.user;
  else
    user = NULL;

  /* Find the password with priority */
  if (u->passwd)
    passwd = u->passwd;
  else if (opt.passwd && (opt.use_askpass || opt.ask_passwd))
    passwd = opt.passwd;
  else if (opt.ftp_passwd)
    passwd = opt.ftp_passwd;
  else if (opt.passwd)
    passwd = opt.passwd;
  else
    passwd = NULL;

  /* Check for ~/.netrc if none of the above match */
  if (opt.netrc && (!user || !passwd))
    search_netrc (u->host, (const char **) &user, (const char **) &passwd, 1, NULL);

  if (!user) user = "anonymous";
  if (!passwd) passwd = "-wget@";

  dtsock = -1;
  local_sock = -1;
  con->dltime = 0;

  if (opt.warc_filename != NULL)
    {
      /* Create the warc_context or rotate it. */
      if (warc_context->ccon_fp == NULL)
        err_tmp = create_warc_context (warc_context, con, u);
      else
        err_tmp = rotate_warc_context (warc_context, con, u, false);
      if (err_tmp != RETROK)
        return err_tmp;
    }

#ifdef HAVE_SSL
  if (u->scheme == SCHEME_FTPS)
    {
      /* Initialize SSL layer first */
      if (!ssl_init ())
        {
          scheme_disable (SCHEME_FTPS);
          logprintf (LOG_NOTQUIET, _("Could not initialize SSL. It will be disabled.\n"));
          err = SSLINITFAILED;
          return err;
        }

      /* If we're using the default FTP port and implicit FTPS was requested,
       * rewrite the port to the default *implicit* FTPS port.
       */
      if (opt.ftps_implicit && u->port == DEFAULT_FTP_PORT)
        {
          DEBUGP (("Implicit FTPS was specified. Rewriting default port to %d.\n", DEFAULT_FTPS_IMPLICIT_PORT));
          u->port = DEFAULT_FTPS_IMPLICIT_PORT;
        }
    }
#endif

  if (!(cmd & DO_LOGIN))
    {
      csock = con->csock;

      err = write_control_message_sock ("Reusing control connection to", NULL,
                                        NULL, csock, NULL, warc_context->ccon_fp);
      if (err != RETROK)
        return err;

      if (opt.warc_filename != NULL
          && !socket_ip_address (csock, &warc_context->ip_addr, ENDPOINT_PEER))
        return CONERROR;

#ifdef HAVE_SSL
      using_data_security = con->st & DATA_CHANNEL_SECURITY;
#endif
    }
  else                          /* cmd & DO_LOGIN */
    {
      /* Login to the server: */

      /* First: Establish the control connection.  */

      char    *host = con->proxy ? con->proxy->host : u->host;
      int      port = con->proxy ? con->proxy->port : u->port;

      if (opt.warc_filename != NULL)
        {
          warc_context->number = 0;
          xzero (warc_context->origin_id_uuid);
        }

      err = write_control_message_host_port ("Opening control connection to",
                                             host, port, NULL, warc_context->ccon_fp);
      if (err != RETROK)
        return err;

      csock = connect_to_host (host, port);

      if (csock == E_HOST || csock < 0)
        {
          err = write_control_message_host_port ("Failed to open control connection to",
                                                host, port, NULL, warc_context->ccon_fp);
          if (err != RETROK)
            return err;
        }

      if (csock == E_HOST)
          return HOSTERR;
      else if (csock < 0)
          return (retryable_socket_connect_error (errno)
                  ? CONERROR : CONIMPOSSIBLE);

      if (cmd & LEAVE_PENDING)
        con->csock = csock;
      else
        con->csock = -1;

      err = write_control_message_sock ("Opened control connection to", NULL,
                                        NULL, csock, NULL, warc_context->ccon_fp);
      if (err != RETROK)
        return err;

      if (opt.warc_filename != NULL
          && !socket_ip_address (csock, &warc_context->ip_addr, ENDPOINT_PEER))
        return CONERROR;

#ifdef HAVE_SSL
      if (u->scheme == SCHEME_FTPS)
        {
          /* If we're in implicit FTPS mode, we have to set up SSL/TLS before everything else.
           * Otherwise we first read the server's greeting, and then send an "AUTH TLS".
           */
          if (opt.ftps_implicit)
            {
              err = init_control_ssl_connection (csock, u, &using_control_security,
                                                 con, warc_context->ccon_fp,
                                                 warc_context);
              if (err != NOCONERROR)
                return err;
              err = get_ftp_greeting (csock, con, warc_context->ccon_fp);
              if (err != FTPOK)
                return err;
            }
          else
            {
              err = get_ftp_greeting (csock, con, warc_context->ccon_fp);
              if (err != FTPOK)
                return err;
              err = init_control_ssl_connection (csock, u, &using_control_security,
                                                 con, warc_context->ccon_fp,
                                                 warc_context);
              if (err != NOCONERROR)
                return err;
            }
        }
      else
        {
          err = get_ftp_greeting (csock, con, warc_context->ccon_fp);
          if (err != FTPOK)
            return err;
        }
#else
      err = get_ftp_greeting (csock, con, warc_context->ccon_fp);
      if (err != FTPOK)
        return err;
#endif

      /* Second: Login with proper USER/PASS sequence.  */
      logprintf (LOG_VERBOSE, _("Logging in as %s ... "),
                 quotearg_style (escape_quoting_style, user));
      if (opt.server_response)
        logputs (LOG_ALWAYS, "\n");
      if (con->proxy)
        {
          /* If proxy is in use, log in as username@target-site. */
          char *logname = concat_strings (user, "@", u->host, (char *) 0);
          err = ftp_login (csock, logname, passwd, warc_context->ccon_fp);
          xfree (logname);
        }
      else
        err = ftp_login (csock, user, passwd, warc_context->ccon_fp);

      /* FTPRERR, FTPSRVERR, WRITEFAILED, FTPLOGREFUSED, FTPLOGINC */
      switch (err)
        {
        case FTPRERR:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
          return close_sock (csock, 0, con, warc_context->ccon_fp, err);
        case FTPSRVERR:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET, _("Error in server greeting.\n"));
          return close_sock (csock, 0, con, warc_context->ccon_fp, err);
        case WRITEFAILED:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET,
                   _("Write failed, closing control connection.\n"));
          return close_sock (csock, 0, con, warc_context->ccon_fp, err);
        case FTPLOGREFUSED:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET, _("The server refuses login.\n"));
          return close_sock (csock, 0, con, warc_context->ccon_fp, err);
        case FTPLOGINC:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET, _("Login incorrect.\n"));
          return close_sock (csock, 0, con, warc_context->ccon_fp, err);
        case FTPOK:
          if (!opt.server_response)
            logputs (LOG_VERBOSE, _("Logged in!\n"));
          break;
        default:
          abort ();
        }

#ifdef HAVE_SSL
      if (using_control_security)
        {
          /* Send the PBSZ and PROT commands, in that order.
           * If we are here it means that the server has already accepted
           * some form of FTPS. Thus, these commands must work.
           * If they don't work, that's an error. There's no sense in honoring
           * --ftps-fallback-to-ftp or similar options. */
          if (u->scheme == SCHEME_FTPS)
            {
              if (!opt.server_response)
                logputs (LOG_VERBOSE, "==> PBSZ 0 ... ");
              if ((err = ftp_pbsz (csock, 0, warc_context->ccon_fp)) == FTPNOPBSZ)
                {
                  logputs (LOG_NOTQUIET, _("Server did not accept the 'PBSZ 0' command.\n"));
                  return err;
                }
              if (!opt.server_response)
                logputs (LOG_VERBOSE, "done.");

              if (!opt.server_response)
                logprintf (LOG_VERBOSE, "  ==> PROT %c ... ", (int) prot);
              if ((err = ftp_prot (csock, prot, warc_context->ccon_fp)) == FTPNOPROT)
                {
                  logprintf (LOG_NOTQUIET, _("Server did not accept the 'PROT %c' command.\n"), (int) prot);
                  return err;
                }
              if (!opt.server_response)
                logputs (LOG_VERBOSE, "done.\n");

              if (prot != PROT_CLEAR)
                {
                  using_data_security = true;
                  con->st |= DATA_CHANNEL_SECURITY;
                }
            }
        }
#endif

      if (opt.warc_filename != NULL)
        {
          /* Extra: Get the system features and run other commands
             to archive the responses. */
          if (!opt.server_response)
            logprintf (LOG_VERBOSE, "==> FEAT ... ");
          err = ftp_feat (csock, warc_context->ccon_fp);
          if (err == FTPOK)
            {
              if (!opt.server_response)
                logprintf (LOG_VERBOSE, "==> HELP ... ");
              err = ftp_help (csock, warc_context->ccon_fp);
            }
          if (err == FTPOK)
            {
              if (!opt.server_response)
                logprintf (LOG_VERBOSE, "==> STAT ... ");
              err = ftp_stat (csock, warc_context->ccon_fp);
            }
          if (err == FTPOK)
            {
              if (!opt.server_response)
                logprintf (LOG_VERBOSE, "==> NOOP ... ");
              err = ftp_noop (csock, warc_context->ccon_fp);
            }
          switch (err)
            {
            case FTPRERR:
              logputs (LOG_VERBOSE, "\n");
              logputs (LOG_NOTQUIET, _("\
    Error in server response, closing control connection.\n"));
              return close_sock (csock, 0, con, warc_context->ccon_fp, err);
            case FTPOK:
              break;
            default:
              abort ();
            }
        }

      if (!opt.server_response && err != FTPSRVERR)
        logputs (LOG_VERBOSE, _("done.    "));

      /* Third: Get the system type */
      if (!opt.server_response)
        logprintf (LOG_VERBOSE, "==> SYST ... ");
      err = ftp_syst (csock, &con->rs, &con->rsu, warc_context->ccon_fp);
      /* FTPRERR */
      switch (err)
        {
        case FTPRERR:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
          return close_sock (csock, 0, con, warc_context->ccon_fp, err);
        case FTPSRVERR:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET,
                   _("Server error, can't determine system type.\n"));
          break;
        case FTPOK:
          /* Everything is OK.  */
          break;
        default:
          abort ();
        }
      if (!opt.server_response && err != FTPSRVERR)
        logputs (LOG_VERBOSE, _("done.    "));

      /* 2013-10-17 Andrea Urbani (matfanjol)
         According to the system type I choose which
         list command will be used.
         If I don't know that system, I will try, the
         first time of each session, "LIST -a" and
         "LIST". (see __LIST_A_EXPLANATION__ below) */
      switch (con->rs)
        {
        case ST_VMS:
          /* About ST_VMS there is an old note:
             2008-01-29  SMS.  For a VMS FTP server, where "LIST -a" may not
             fail, but will never do what is desired here,
             skip directly to the simple "LIST" command
             (assumed to be the last one in the list).  */
          DEBUGP (("\nVMS: I know it and I will use \"LIST\" as standard list command\n"));
          con->st |= LIST_AFTER_LIST_A_CHECK_DONE;
          con->st |= AVOID_LIST_A;
          break;
        case ST_UNIX:
          if (con->rsu == UST_MULTINET)
            {
              DEBUGP (("\nUNIX MultiNet: I know it and I will use \"LIST\" "
                       "as standard list command\n"));
              con->st |= LIST_AFTER_LIST_A_CHECK_DONE;
              con->st |= AVOID_LIST_A;
            }
          else if (con->rsu == UST_TYPE_L8)
            {
              DEBUGP (("\nUNIX TYPE L8: I know it and I will use \"LIST -a\" "
                       "as standard list command\n"));
              con->st |= LIST_AFTER_LIST_A_CHECK_DONE;
              con->st |= AVOID_LIST;
            }
          break;
        default:
          break;
        }

      /* Fourth: Find the initial ftp directory */

      if (!opt.server_response)
        logprintf (LOG_VERBOSE, "==> PWD ... ");
      err = ftp_pwd (csock, &con->id, warc_context->ccon_fp);
      /* FTPRERR */
      switch (err)
        {
        case FTPRERR:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
          return close_sock (csock, 0, con, warc_context->ccon_fp, err);
        case FTPSRVERR :
          /* PWD unsupported -- assume "/". */
          xfree (con->id);
          con->id = xstrdup ("/");
          break;
        case FTPOK:
          /* Everything is OK.  */
          break;
        default:
          abort ();
        }

#if 0
      /* 2004-09-17 SMS.
         Don't help me out.  Please.
         A reasonably recent VMS FTP server will cope just fine with
         UNIX file specifications.  This code just spoils things.
         Discarding the device name, for example, is not a wise move.
         This code was disabled but left in as an example of what not
         to do.
      */

      /* VMS will report something like "PUB$DEVICE:[INITIAL.FOLDER]".
         Convert it to "/INITIAL/FOLDER" */
      if (con->rs == ST_VMS)
        {
          char *path = strchr (con->id, '[');
          char *pathend = path ? strchr (path + 1, ']') : NULL;
          if (!path || !pathend)
            DEBUGP (("Initial VMS directory not in the form [...]!\n"));
          else
            {
              char *idir = con->id;
              DEBUGP (("Preprocessing the initial VMS directory\n"));
              DEBUGP (("  old = '%s'\n", con->id));
              /* We do the conversion in-place by copying the stuff
                 between [ and ] to the beginning, and changing dots
                 to slashes at the same time.  */
              *idir++ = '/';
              for (++path; path < pathend; path++, idir++)
                *idir = *path == '.' ? '/' : *path;
              *idir = '\0';
              DEBUGP (("  new = '%s'\n\n", con->id));
            }
        }
#endif /* 0 */

      if (!opt.server_response)
        logputs (LOG_VERBOSE, _("done.\n"));

      /* Fifth: Set the FTP type.  */
      type_char = ftp_process_type (u->params);
      if (!opt.server_response)
        logprintf (LOG_VERBOSE, "==> TYPE %c ... ", type_char);
      err = ftp_type (csock, type_char, warc_context->ccon_fp);
      /* FTPRERR, WRITEFAILED, FTPUNKNOWNTYPE */
      switch (err)
        {
        case FTPRERR:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
          return close_sock (csock, 0, con, warc_context->ccon_fp, err);
        case WRITEFAILED:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET,
                   _("Write failed, closing control connection.\n"));
          return close_sock (csock, 0, con, warc_context->ccon_fp, err);
        case FTPUNKNOWNTYPE:
          logputs (LOG_VERBOSE, "\n");
          logprintf (LOG_NOTQUIET,
                     _("Unknown type `%c', closing control connection.\n"),
                     type_char);
          return close_sock (csock, 0, con, warc_context->ccon_fp, err);
        case FTPOK:
          /* Everything is OK.  */
          break;
        default:
          abort ();
        }
      if (!opt.server_response)
        logputs (LOG_VERBOSE, _("done.  "));
    } /* do login */

  if (cmd & DO_CWD)
    {
      if (!*u->dir)
        logputs (LOG_VERBOSE, _("==> CWD not needed.\n"));
      else
        {
          const char *targ = NULL;
          char *target = u->dir;
          char targetbuf[1024];
          int cwd_count;
          int cwd_end;
          int cwd_start;

          DEBUGP (("changing working directory\n"));

          /* Change working directory.  To change to a non-absolute
             Unix directory, we need to prepend initial directory
             (con->id) to it.  Absolute directories "just work".

             A relative directory is one that does not begin with '/'
             and, on non-Unix OS'es, one that doesn't begin with
             "[a-z]:".

             This is not done for OS400, which doesn't use
             "/"-delimited directories, nor does it support directory
             hierarchies.  "CWD foo" followed by "CWD bar" leaves us
             in "bar", not in "foo/bar", as would be customary
             elsewhere.  */

            /* 2004-09-20 SMS.
               Why is this wise even on UNIX?  It certainly fouls VMS.
               See below for a more reliable, more universal method.
            */

            /* 2008-04-22 MJC.
               I'm not crazy about it either. I'm informed it's useful
               for misconfigured servers that have some dirs in the path
               with +x but -r, but this method is not RFC-conformant. I
               understand the need to deal with crappy server
               configurations, but it's far better to use the canonical
               method first, and fall back to kludges second.
            */

          if (target[0] != '/'
              && !(con->rs != ST_UNIX
                   && c_isalpha (target[0])
                   && target[1] == ':')
              && (con->rs != ST_OS400)
              && (con->rs != ST_VMS))
            {
              char *ntarget, *p;
              size_t idlen = strlen (con->id);
              size_t len;

              /* Strip trailing slash(es) from con->id. */
              while (idlen > 0 && con->id[idlen - 1] == '/')
                --idlen;

              len = idlen + 1 + strlen (target);
              if (len < sizeof (targetbuf))
                p = ntarget = targetbuf;
              else
                p = ntarget = xmalloc (len + 1);

              memcpy (p, con->id, idlen);
              p += idlen;
              *p++ = '/';
              strcpy (p, target);

              DEBUGP (("Prepended initial PWD to relative path:\n"));
              DEBUGP (("   pwd: '%s'\n   old: '%s'\n  new: '%s'\n",
                       con->id, target, ntarget));
              target = ntarget;
            }

#if 0
          /* 2004-09-17 SMS.
             Don't help me out.  Please.
             A reasonably recent VMS FTP server will cope just fine with
             UNIX file specifications.  This code just spoils things.
             Discarding the device name, for example, is not a wise
             move.
             This code was disabled but left in as an example of what
             not to do.
          */

          /* If the FTP host runs VMS, we will have to convert the absolute
             directory path in UNIX notation to absolute directory path in
             VMS notation as VMS FTP servers do not like UNIX notation of
             absolute paths.  "VMS notation" is [dir.subdir.subsubdir]. */

          if (con->rs == ST_VMS)
            {
              char *tmpp;
              char *ntarget = alloca (strlen (target) + 2);
              /* We use a converted initial dir, so directories in
                 TARGET will be separated with slashes, something like
                 "/INITIAL/FOLDER/DIR/SUBDIR".  Convert that to
                 "[INITIAL.FOLDER.DIR.SUBDIR]".  */
              strcpy (ntarget, target);
              assert (*ntarget == '/');
              *ntarget = '[';
              for (tmpp = ntarget + 1; *tmpp; tmpp++)
                if (*tmpp == '/')
                  *tmpp = '.';
              *tmpp++ = ']';
              *tmpp = '\0';
              DEBUGP (("Changed file name to VMS syntax:\n"));
              DEBUGP (("  Unix: '%s'\n  VMS: '%s'\n", target, ntarget));
              target = ntarget;
            }
#endif /* 0 */

          /* 2004-09-20 SMS.
             A relative directory is relative to the initial directory.
             Thus, what _is_ useful on VMS (and probably elsewhere) is
             to CWD to the initial directory (ideally, whatever the
             server reports, _exactly_, NOT badly UNIX-ixed), and then
             CWD to the (new) relative directory.  This should probably
             be restructured as a function, called once or twice, but
             I'm lazy enough to take the badly indented loop short-cut
             for now.
          */

          /* Decide on one pass (absolute) or two (relative).
             The VMS restriction may be relaxed when the squirrely code
             above is reformed.
          */
          if ((con->rs == ST_VMS) && (target[0] != '/'))
            {
              cwd_start = 0;
              DEBUGP (("Using two-step CWD for relative path.\n"));
            }
          else
            {
              /* Go straight to the target. */
              cwd_start = 1;
            }

          /* At least one VMS FTP server (TCPware V5.6-2) can switch to
             a UNIX emulation mode when given a UNIX-like directory
             specification (like "a/b/c").  If allowed to continue this
             way, LIST interpretation will be confused, because the
             system type (SYST response) will not be re-checked, and
             future UNIX-format directory listings (for multiple URLs or
             "-r") will be horribly misinterpreted.

             The cheap and nasty work-around is to do a "CWD []" after a
             UNIX-like directory specification is used.  (A single-level
             directory is harmless.)  This puts the TCPware server back
             into VMS mode, and does no harm on other servers.

             Unlike the rest of this block, this particular behavior
             _is_ VMS-specific, so it gets its own VMS test.
          */
          if ((con->rs == ST_VMS) && (strchr (target, '/') != NULL))
            {
              cwd_end = 3;
              DEBUGP (("Using extra \"CWD []\" step for VMS server.\n"));
            }
          else
            {
              cwd_end = 2;
            }

          /* 2004-09-20 SMS. */
          /* Sorry about the deviant indenting.  Laziness. */

          for (cwd_count = cwd_start; cwd_count < cwd_end; cwd_count++)
            {
              switch (cwd_count)
                {
                  case 0:
                    /* Step one (optional): Go to the initial directory,
                       exactly as reported by the server.
                    */
                    targ = con->id;
                    break;

                  case 1:
                    /* Step two: Go to the target directory.  (Absolute or
                       relative will work now.)
                    */
                    targ = target;
                    break;

                  case 2:
                    /* Step three (optional): "CWD []" to restore server
                       VMS-ness.
                    */
                    targ = "[]";
                    break;

                  default:
                    logprintf (LOG_ALWAYS, _("Logically impossible section reached in getftp()"));
                    logprintf (LOG_ALWAYS, _("cwd_count: %d\ncwd_start: %d\ncwd_end: %d\n"),
                                             cwd_count, cwd_start, cwd_end);
                    abort ();
                }

              if (!opt.server_response)
                logprintf (LOG_VERBOSE, "==> CWD (%d) %s ... ", cwd_count,
                           quotearg_style (escape_quoting_style, target));

              err = ftp_cwd (csock, targ, warc_context->ccon_fp);

              /* FTPRERR, WRITEFAILED, FTPNSFOD */
              switch (err)
                {
                  case FTPRERR:
                    logputs (LOG_VERBOSE, "\n");
                    logputs (LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
                    return close_sock (csock, 0, con, warc_context->ccon_fp, err);
                  case WRITEFAILED:
                    logputs (LOG_VERBOSE, "\n");
                    logputs (LOG_NOTQUIET,
                             _("Write failed, closing control connection.\n"));
                    return close_sock (csock, 0, con, warc_context->ccon_fp, err);
                  case FTPNSFOD:
                    logputs (LOG_VERBOSE, "\n");
                    logprintf (LOG_NOTQUIET, _("No such directory %s.\n\n"),
                               quote (u->dir));
                    return close_sock (csock, 0, con, warc_context->ccon_fp, err);
                  case FTPOK:
                    break;
                  default:
                    abort ();
                }

              if (!opt.server_response)
                logputs (LOG_VERBOSE, _("done.\n"));

            } /* for */

          /* 2004-09-20 SMS. */

        } /* else */
    }
  else /* do not CWD */
    logputs (LOG_VERBOSE, _("==> CWD not required.\n"));

  if ((cmd & DO_RETR) && passed_expected_bytes == 0)
    {
      if (opt.verbose)
        {
          if (!opt.server_response)
            logprintf (LOG_VERBOSE, "==> SIZE %s ... ",
                       quotearg_style (escape_quoting_style, u->file));
        }

      err = ftp_size (csock, u->file, &expected_bytes, warc_context->ccon_fp);
      /* FTPRERR */
      switch (err)
        {
        case FTPRERR:
        case FTPSRVERR:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
          return close_sock (csock, 0, con, warc_context->ccon_fp, err);
        case FTPOK:
          got_expected_bytes = true;
          /* Everything is OK.  */
          break;
        default:
          abort ();
        }
        if (!opt.server_response)
          {
            logprintf (LOG_VERBOSE, "%s\n",
                    expected_bytes ?
                    number_to_static_string (expected_bytes) :
                    _("done.\n"));
          }
    }

  if (cmd & DO_RETR && restval > 0 && restval == expected_bytes)
    {
      /* Server confirms that file has length restval. We should stop now.
         Some servers (f.e. NcFTPd) return error when receive REST 0 */
      logputs (LOG_VERBOSE, _("File has already been retrieved.\n"));
      return close_sock (csock, 0, con, warc_context->ccon_fp, RETRFINISHED);
    }

  do
  {
  try_again = false;

  if (opt.warc_filename && warc_context->written_resource)
    {
      /* If the resource was previously correctly written, it is written
         out in the WARC resource record, together with the WARC metadata
         record and new file file pointers are prepared. */
      err_tmp = rotate_warc_context (warc_context, con, u, false);
      if (err_tmp != RETROK)
        return err_tmp;

      if (!socket_ip_address (csock, &warc_context->ip_addr, ENDPOINT_PEER))
        return CONERROR;

      /* Note the control connection is reused. */
      err_tmp = write_control_message_sock ("Reusing control connection to", NULL,
                                            NULL, csock, NULL, warc_context->ccon_fp);
      if (err_tmp != RETROK)
        return err_tmp;
    }

  /* If anything is to be retrieved, PORT (or PASV) must be sent.  */
  if (cmd & (DO_LIST | DO_RETR))
    {
      if (opt.ftp_pasv)
        {
          ip_address passive_addr;
          int        passive_port;
          err = ftp_do_pasv (csock, &passive_addr, &passive_port,
                             warc_context->ccon_fp);
          /* FTPRERR, WRITEFAILED, FTPNOPASV, FTPINVPASV */
          switch (err)
            {
            case FTPRERR:
              logputs (LOG_VERBOSE, "\n");
              logputs (LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
              return close_sock (csock, 0, con, warc_context->ccon_fp, err);
            case WRITEFAILED:
              logputs (LOG_VERBOSE, "\n");
              logputs (LOG_NOTQUIET,
                       _("Write failed, closing control connection.\n"));
              return close_sock (csock, 0, con, warc_context->ccon_fp, err);
            case FTPNOPASV:
              logputs (LOG_VERBOSE, "\n");
              logputs (LOG_NOTQUIET, _("Cannot initiate PASV transfer.\n"));
              break;
            case FTPINVPASV:
              logputs (LOG_VERBOSE, "\n");
              logputs (LOG_NOTQUIET, _("Cannot parse PASV response.\n"));
              break;
            case FTPOK:
              break;
            default:
              abort ();
            }   /* switch (err) */
          if (err==FTPOK)
            {
              DEBUGP (("trying to connect to %s port %d\n",
                      print_address (&passive_addr), passive_port));
              err = write_control_message_host_port ("Opening data connection to",
                                    print_address (&passive_addr),
                                    passive_port, NULL, warc_context->ccon_fp);
              if (err != RETROK)
                return err;
              dtsock = connect_to_ip (&passive_addr, passive_port, NULL);
              if (dtsock < 0)
                {
                  int save_errno = errno;
                  err = write_control_message_host_port ("Failed to open data connection to",
                                    print_address (&passive_addr), passive_port,
                                    NULL, warc_context->ccon_fp);
                  if (err != RETROK)
                    return err;
                  err = close_sock (csock, 0, con, warc_context->ccon_fp, RETROK);
                  if (err != RETROK)
                    return err;
                  logprintf (LOG_VERBOSE, _("couldn't connect to %s port %d: %s\n"),
                             print_address (&passive_addr), passive_port,
                             strerror (save_errno));
                  return (retryable_socket_connect_error (save_errno)
                          ? CONERROR : CONIMPOSSIBLE);
                }

              err = write_control_message_sock ("Opened data connection to",
                                    NULL, NULL, dtsock, NULL, warc_context->ccon_fp);
              if (err != RETROK)
                return err;

              if (!opt.server_response)
                logputs (LOG_VERBOSE, _("done.    "));
            }
          else
            return err;

          /*
           * We do not want to fall back from PASSIVE mode to ACTIVE mode !
           * The reason is the PORT command exposes the client's real IP address
           * to the server. Bad for someone who relies on privacy via a ftp proxy.
           */
        }
      else
        {
          err = ftp_do_port (csock, &local_sock, warc_context->ccon_fp);
          /* FTPRERR, WRITEFAILED, bindport (FTPSYSERR), HOSTERR,
             FTPPORTERR */
          switch (err)
            {
            case FTPRERR:
              logputs (LOG_VERBOSE, "\n");
              logputs (LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
              err = close_sock (csock, dtsock, con, warc_context->ccon_fp, err);
              fd_close (local_sock);
              return err;
            case WRITEFAILED:
              logputs (LOG_VERBOSE, "\n");
              logputs (LOG_NOTQUIET,
                       _("Write failed, closing control connection.\n"));
              err = close_sock (csock, dtsock, con, warc_context->ccon_fp, err);
              fd_close (local_sock);
              return err;
            case CONSOCKERR:
              logputs (LOG_VERBOSE, "\n");
              logprintf (LOG_NOTQUIET, "socket: %s\n", strerror (errno));
              err = close_sock (csock, dtsock, con, warc_context->ccon_fp, err);
              fd_close (local_sock);
              return err;
            case FTPSYSERR:
              logputs (LOG_VERBOSE, "\n");
              logprintf (LOG_NOTQUIET, _("Bind error (%s).\n"),
                         strerror (errno));
              err = close_sock (0, dtsock, con, warc_context->ccon_fp, err);
              return err;
            case FTPPORTERR:
              logputs (LOG_VERBOSE, "\n");
              logputs (LOG_NOTQUIET, _("Invalid PORT.\n"));
              err = close_sock (csock, dtsock, con, warc_context->ccon_fp, err);
              fd_close (local_sock);
              return err;
            case FTPOK:
              break;
            default:
              abort ();
            } /* port switch */
          if (!opt.server_response)
            logputs (LOG_VERBOSE, _("done.    "));
        } /* dtsock == -1 */
    } /* cmd & (DO_LIST | DO_RETR) */

  /* Restart if needed.  */
  if (restval && (cmd & DO_RETR))
    {
      if (!opt.server_response)
        logprintf (LOG_VERBOSE, "==> REST %s ... ",
                   number_to_static_string (restval));
      err = ftp_rest (csock, restval, warc_context->ccon_fp);

      /* FTPRERR, WRITEFAILED, FTPRESTFAIL */
      switch (err)
        {
        case FTPRERR:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
          err = close_sock (csock, dtsock, con, warc_context->ccon_fp, err);
          fd_close (local_sock);
          return err;
        case WRITEFAILED:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET,
                   _("Write failed, closing control connection.\n"));
          err = close_sock (csock, dtsock, con, warc_context->ccon_fp, err);
          fd_close (local_sock);
          return err;
        case FTPRESTFAIL:
          logputs (LOG_VERBOSE, _("\nREST failed, starting from scratch.\n"));
          rest_failed = true;
          break;
        case FTPOK:
          break;
        default:
          abort ();
        }
      if (err != FTPRESTFAIL && !opt.server_response)
        logputs (LOG_VERBOSE, _("done.    "));
    } /* restval && cmd & DO_RETR */

  if (cmd & DO_RETR)
    {
      /* If we're in spider mode, don't really retrieve anything except
         the directory listing and verify whether the given "file" exists.  */
      if (opt.spider)
        {
          bool exists = false;
          bool all_exist = true;
          struct fileinfo *f;
          uerr_t _res = ftp_get_listing (u, original_url, con, &f, warc_context,
                                         NULL, NULL);
          /* Set the DO_RETR command flag again, because it gets unset when
             calling ftp_get_listing() and would otherwise cause an assertion
             failure earlier on when this function gets repeatedly called
             (e.g., when recursing).  */
          con->cmd |= DO_RETR;
          if (_res == RETROK)
            {
              while (f)
                {
                  if (!strcmp (f->name, u->file))
                    {
                      exists = true;
                      break;
                    } else {
                      all_exist = false;
                    }
                  f = f->next;
                }
              if (exists)
                {
                  logputs (LOG_VERBOSE, "\n");
                  logprintf (LOG_NOTQUIET, _("File %s exists.\n"),
                             quote (u->file));
                }
              else
                {
                  logputs (LOG_VERBOSE, "\n");
                  logprintf (LOG_NOTQUIET, _("No such file %s.\n"),
                             quote (u->file));
                }
            }
          err = close_sock (csock, dtsock, con, warc_context->ccon_fp, RETROK);
          if (err != RETROK)
            return err;
          fd_close (local_sock);
          if (all_exist) {
              return RETRFINISHED;
          } else {
              return FTPNSFOD;
          }
        }

      if (opt.verbose)
        {
          if (!opt.server_response)
            {
              if (restval)
                logputs (LOG_VERBOSE, "\n");
              logprintf (LOG_VERBOSE, "==> RETR %s ... ",
                         quotearg_style (escape_quoting_style, u->file));
            }
        }

      err = ftp_retr (csock, u->file, warc_context->ccon_fp);
      /* FTPRERR, WRITEFAILED, FTPNSFOD */
      switch (err)
        {
        case FTPRERR:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
          err = close_sock (csock, dtsock, con, warc_context->ccon_fp, err);
          fd_close (local_sock);
          return err;
        case WRITEFAILED:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET,
                   _("Write failed, closing control connection.\n"));
          err = close_sock (csock, dtsock, con, warc_context->ccon_fp, err);
          fd_close (local_sock);
          return err;
        case FTPNSFOD:
          logputs (LOG_VERBOSE, "\n");
          logprintf (LOG_NOTQUIET, _("No such file %s.\n\n"),
                     quote (u->file));
          err = close_sock (0, dtsock, con, warc_context->ccon_fp, err);
          fd_close (local_sock);
          return err;
        case FTPOK:
          break;
        default:
          abort ();
        }

      if (!opt.server_response)
        logputs (LOG_VERBOSE, _("done.\n"));

      if (! got_expected_bytes)
        expected_bytes = *last_expected_bytes;
    } /* do retrieve */

  if (cmd & DO_LIST)
    {
      if (!opt.server_response)
        logputs (LOG_VERBOSE, "==> LIST ... ");
      /* As Maciej W. Rozycki (macro@ds2.pg.gda.pl) says, `LIST'
         without arguments is better than `LIST .'; confirmed by
         RFC959.  */
      err = ftp_list (csock, NULL, con->st&AVOID_LIST_A, con->st&AVOID_LIST,
                      &list_a_used, warc_context->ccon_fp);

      /* FTPRERR, WRITEFAILED */
      switch (err)
        {
        case FTPRERR:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
          err = close_sock (csock, dtsock, con, warc_context->ccon_fp, err);
          fd_close (local_sock);
          return err;
        case WRITEFAILED:
          logputs (LOG_VERBOSE, "\n");
          logputs (LOG_NOTQUIET,
                   _("Write failed, closing control connection.\n"));
          err = close_sock (csock, dtsock, con, warc_context->ccon_fp, err);
          fd_close (local_sock);
          return err;
        case FTPNSFOD:
          logputs (LOG_VERBOSE, "\n");
          logprintf (LOG_NOTQUIET, _("No such file or directory %s.\n\n"),
                     quote ("."));
          err = close_sock (0, dtsock, con, warc_context->ccon_fp, err);
          fd_close (local_sock);
          return err;
        case FTPOK:
          break;
        default:
          abort ();
        }
      if (!opt.server_response)
        logputs (LOG_VERBOSE, _("done.\n"));

      if (! got_expected_bytes)
        expected_bytes = *last_expected_bytes;
    } /* cmd & DO_LIST */

  if (!(cmd & (DO_LIST | DO_RETR)) || (opt.spider && !(cmd & DO_LIST)))
    return RETRFINISHED;

  /* Some FTP servers return the total length of file after REST
     command, others just return the remaining size. */
  if (passed_expected_bytes && restval && expected_bytes
      && (expected_bytes == passed_expected_bytes - restval))
    {
      DEBUGP (("Lying FTP server found, adjusting.\n"));
      expected_bytes = passed_expected_bytes;
    }

  /* If no transmission was required, then everything is OK.  */
  if (!opt.ftp_pasv)  /* we are not using passive mode so we need
                         to accept */
    {
      /* Wait for the server to connect to the address we're waiting
         at.  */
      dtsock = accept_connection (local_sock);
      if (dtsock < 0)
        {
          logprintf (LOG_NOTQUIET, "accept: %s\n", strerror (errno));
          return CONERROR;
        }
    }

  /* Open the file -- if output_stream is set, use it instead.  */

  /* 2005-04-17 SMS.
     Note that having the output_stream ("-O") file opened in main
     (main.c) rather limits the ability in VMS to open the file
     differently for ASCII versus binary FTP here.  (Of course, doing it
     there allows a open failure to be detected immediately, without first
     connecting to the server.)
  */
  if (!output_stream || con->cmd & DO_LIST)
    {
/* On VMS, alter the name as required. */
#ifdef __VMS
      char *targ;

      targ = ods_conform (con->target);
      if (targ != con->target)
        {
          xfree (con->target);
          con->target = targ;
        }
#endif /* def __VMS */

      mkalldirs (con->target);
      if (opt.backups)
        rotate_backups (con->target);

/* 2005-04-15 SMS.
   For VMS, define common fopen() optional arguments, and a handy macro
   for use as a variable "binary" flag.
   Elsewhere, define a constant "binary" flag.
   Isn't it nice to have distinct text and binary file types?
*/
/* 2011-09-30 SMS.
   Added listing files to the set of non-"binary" (text, Stream_LF)
   files.  (Wget works either way, but other programs, like, say, text
   editors, work better on listing files which have text attributes.)
   Now we use "binary" attributes for a binary ("IMAGE") transfer,
   unless "--ftp-stmlf" was specified, and we always use non-"binary"
   (text, Stream_LF) attributes for a listing file, or for an ASCII
   transfer.
   Tidied the VMS-specific BIN_TYPE_xxx macros, and changed the call to
   fopen_excl() (restored?) to use BIN_TYPE_FILE instead of "true".
*/
#ifdef __VMS
# define BIN_TYPE_TRANSFER (type_char != 'A')
# define BIN_TYPE_FILE \
   ((!(cmd & DO_LIST)) && BIN_TYPE_TRANSFER && (opt.ftp_stmlf == 0))
# define FOPEN_OPT_ARGS "fop=sqo", "acc", acc_cb, &open_id
# define FOPEN_OPT_ARGS_BIN "ctx=bin,stm", "rfm=fix", "mrs=512" FOPEN_OPT_ARGS
#else /* def __VMS */
# define BIN_TYPE_FILE true
#endif /* def __VMS [else] */

      if (restval && !(con->cmd & DO_LIST))
        {
#ifdef __VMS
          int open_id;

          if (BIN_TYPE_FILE)
            {
              open_id = 3;
              fp = fopen (con->target, "ab", FOPEN_OPT_ARGS_BIN);
            }
          else
            {
              open_id = 4;
              fp = fopen (con->target, "a", FOPEN_OPT_ARGS);
            }
#else /* def __VMS */
          fp = fopen (con->target, "ab");
#endif /* def __VMS [else] */
        }
      else if (opt.noclobber || opt.always_rest || opt.timestamping || opt.dirstruct
               || opt.output_document || count > 0)
        {
          if (opt.unlink_requested && file_exists_p (con->target, NULL))
            {
              if (unlink (con->target) < 0)
                {
                  logprintf (LOG_NOTQUIET, "%s: %s\n", con->target,
                    strerror (errno));
                    err = close_sock (csock, dtsock, con, warc_context->ccon_fp, UNLINKERR);
                    fd_close (local_sock);
                    return err;
                }
            }

#ifdef __VMS
          int open_id;

          if (BIN_TYPE_FILE)
            {
              open_id = 5;
              fp = fopen (con->target, "wb", FOPEN_OPT_ARGS_BIN);
            }
          else
            {
              open_id = 6;
              fp = fopen (con->target, "w", FOPEN_OPT_ARGS);
            }
#else /* def __VMS */
          fp = fopen (con->target, "wb");
#endif /* def __VMS [else] */
        }
      else
        {
          fp = fopen_excl (con->target, BIN_TYPE_FILE);
          if (!fp && errno == EEXIST)
            {
              /* We cannot just invent a new name and use it (which is
                 what functions like unique_create typically do)
                 because we told the user we'd use this name.
                 Instead, return and retry the download.  */
              logprintf (LOG_NOTQUIET, _("%s has sprung into existence.\n"),
                         con->target);
              err = close_sock (csock, dtsock, con, warc_context->ccon_fp, FOPEN_EXCL_ERR);
              fd_close (local_sock);
              return err;
            }
        }
      if (!fp)
        {
          logprintf (LOG_NOTQUIET, "%s: %s\n", con->target, strerror (errno));
          err = close_sock (csock, dtsock, con, warc_context->ccon_fp, FOPENERR);
          fd_close (local_sock);
          return err;
        }
    }
  else
    fp = output_stream;

  if (passed_expected_bytes)
    {
      print_length (passed_expected_bytes, restval, true);
      expected_bytes = passed_expected_bytes;
        /* for fd_read_body's progress bar */
    }
  else if (expected_bytes)
    print_length (expected_bytes, restval, false);

#ifdef HAVE_SSL
  if (u->scheme == SCHEME_FTPS && using_data_security)
    {
      /* We should try to restore the existing SSL session in the data connection
       * and fall back to establishing a new session if the server doesn't want to restore it.
       */

      /* When resuming an SSL session for the data connection, the event
         message holds the address for which the SSL session was previously
         created. */
      char *ip_str, *port_str;
      bool is_ipv6;

      if (socket_to_string (&ip_str, &port_str, &is_ipv6, csock) != RETROK)
        return WARC_ERR;

      tmp = concat_strings (" for host ", u->host, " using SSL session from ",
                            is_ipv6 ? "[" : "",ip_str, is_ipv6 ? "]" : "",
                            ":", port_str, ".", (char *) 0);
      xfree (ip_str);
      xfree (port_str);

      if (opt.ftps_resume_ssl
          && write_control_message_sock ("Resuming SSL handshake on", NULL, NULL,
                                    dtsock, tmp, warc_context->ccon_fp) != RETROK)
        {
          xfree (tmp);
          return WARC_TMP_FWRITEERR;
        }
      if (!opt.ftps_resume_ssl || !ssl_connect_wget (dtsock, u->host, &csock))
        {
          if (opt.ftps_resume_ssl)
            {
              logputs (LOG_NOTQUIET, "Server does not want to resume the SSL session. Trying with a new one.\n");
              if (write_control_message_sock ("Failed to resume SSL handshake on",
                                    NULL, NULL, dtsock, tmp,
                                    warc_context->ccon_fp) != RETROK)
                {
                  xfree (tmp);
                  return WARC_TMP_FWRITEERR;
                }
            }

          if (write_control_message_ssl_connection ("Performing", dtsock, u,
                                    warc_context->ccon_fp) != RETROK)
            return WARC_TMP_FWRITEERR;

          if (!ssl_connect_wget (dtsock, u->host, NULL))
            {
              if (write_control_message_ssl_connection ("Failed to perform",
                                    dtsock, u, warc_context->ccon_fp) != RETROK)
                return WARC_TMP_FWRITEERR;
              err = close_sock (csock, dtsock, con, warc_context->ccon_fp, CONERROR);
              logputs (LOG_NOTQUIET, "Could not perform SSL handshake.\n");
              goto exit_error;
            }

          if (write_control_message_ssl_connection ("Performed", dtsock, u,
                                    warc_context->ccon_fp) != RETROK)
            return WARC_TMP_FWRITEERR;
        }
      else
        {
          if (write_control_message_sock ("Resumed SSL handshake on", NULL, NULL,
                                    dtsock, tmp, warc_context->ccon_fp) != RETROK)
            {
              xfree (tmp);
              return WARC_TMP_FWRITEERR;
            }

          logputs (LOG_NOTQUIET, "Resuming SSL session in data connection.\n");
        }

      xfree (tmp);

      if (!ssl_check_certificate (dtsock, u->host))
        {
          err = close_sock (csock, dtsock, con, warc_context->ccon_fp, CONERROR);
          goto exit_error;
        }

      if (opt.warc_filename != NULL)
        {
          warc_context->dtsock_protocol = ssl_get_protocol (dtsock);
          warc_context->dtsock_cipher_name = ssl_get_cipher_name (dtsock);
        }
    }
#endif

  /* Make sure we are cleared to receive data for the WARC resource record. */
  if (opt.warc_filename && warc_context->written_resource)
    return WARC_ERR;

  if (restval != 0)
    {
      logputs (LOG_NOTQUIET, "Partial file should not be downloaded when writing a WARC.\n");
      return WARC_ERR;
    }

  /* Get the contents of the document.  */
  flags = 0;
  if (restval && rest_failed)
    flags |= rb_skip_startpos;
  rd_size = 0;

  /* Store information for the partial http_stat for the Lua hooks. */
  if (opt.warc_filename != NULL)
    {
      warc_context->hstatp->len = restval;
      warc_context->hstatp->rd_size = rd_size;
      warc_context->hstatp->local_file = con->target;
      warc_context->hstatp->restval = restval;
      warc_context->hstatp->dltime = 0;
      warc_context->hstatp->contlen = expected_bytes;
      /* The data connection IP may be different from the control
         connection IP, so retrieve and store this. */
      if (!socket_ip_address (dtsock, &warc_context->ip_addr_data, ENDPOINT_PEER))
        return CONERROR;
    }

  res = fd_read_body (con->target, dtsock, fp,
                      expected_bytes ? expected_bytes - restval : 0,
                      restval, &rd_size, qtyread, &con->dltime, flags,
                      warc_context->fp, NULL);

  if (opt.warc_filename != NULL)
    {
      warc_context->hstatp->rd_size = rd_size;
      warc_context->hstatp->res = res;
      warc_context->hstatp->dltime = con->dltime;
      warc_context->hstatp->rderrmsg = xstrdup (fd_errstr (dtsock));
    }

  tms = datetime_str (time (NULL));
  tmrate = retr_rate (rd_size, con->dltime);
  total_download_time += con->dltime;

#ifdef ENABLE_XATTR
  if (opt.enable_xattr)
    set_file_metadata (u, NULL, fp);
#endif

  fd_close (local_sock);
  /* Close the local file.  */
  if (!output_stream || con->cmd & DO_LIST)
    fclose (fp);

  /* Write an event message for the received bytes. */
  sprintf (rd_size_s, "%d", rd_size);
  received_msg = concat_strings ("Received ", rd_size_s, " bytes\r\n", (char *) 0);
  if (write_control_message_event (received_msg, -1,
                                   warc_context->ccon_fp) < 0)
    return WARC_TMP_FWRITEERR;
  xfree (received_msg);

  /* If fd_read_body couldn't write to fp or warc_context->fp, bail out.  */
  if (res == -2 || (warc_context->fp != NULL && res == -3))
    {
      logprintf (LOG_NOTQUIET, _("%s: %s, closing control connection.\n"),
                 con->target, strerror (errno));
      err_tmp = close_sock (csock, dtsock, con, warc_context->ccon_fp, RETROK);
      if (err_tmp != RETROK)
        return err_tmp;
      if (res == -2)
        return FWRITEERR;
      else if (res == -3)
        return WARC_TMP_FWRITEERR;
    }
  else if (res == -1)
    {
      logprintf (LOG_NOTQUIET, _("%s (%s) - Data connection: %s; "),
                 tms, tmrate, fd_errstr (dtsock));
      if (opt.server_response)
        logputs (LOG_ALWAYS, "\n");
    }
  err_tmp = close_sock (0, dtsock, con, warc_context->ccon_fp, RETROK);
  if (err_tmp != RETROK)
    return err_tmp;

  /* Get the server to tell us if everything is retrieved.  */
  err = ftp_response (csock, &respline, warc_context->ccon_fp);
  if (err != FTPOK)
    {
      /* The control connection is decidedly closed.  Print the time
         only if it hasn't already been printed.  */
      if (res != -1)
        logprintf (LOG_NOTQUIET, "%s (%s) - ", tms, tmrate);
      logputs (LOG_NOTQUIET, _("Control connection closed.\n"));
      /* If there is an error on the control connection, close it, but
         return FTPRETRINT, since there is a possibility that the
         whole file was retrieved nevertheless (but that is for
         ftp_loop_internal to decide).  */
      return close_sock (csock, 0, con, warc_context->ccon_fp, FTPRETRINT);
    } /* err != FTPOK */
  *last_expected_bytes = ftp_expected_bytes (respline);
  /* If retrieval failed for any reason, return FTPRETRINT, but do not
     close socket, since the control connection is still alive.  If
     there is something wrong with the control connection, it will
     become apparent later.  */
  if (*respline != '2')
    {
      if (res != -1)
        logprintf (LOG_NOTQUIET, "%s (%s) - ", tms, tmrate);

      if (write_control_message_event ("Data transfer aborted\r\n", -1,
                                       warc_context->ccon_fp) < 0)
        return WARC_TMP_FWRITEERR;

      logputs (LOG_NOTQUIET, _("Data transfer aborted.\n"));
#ifdef HAVE_SSL
      if (!c_strncasecmp (respline, "425", 3) && u->scheme == SCHEME_FTPS)
        {
          logputs (LOG_NOTQUIET, "FTPS server rejects new SSL sessions in the data connection.\n");
          xfree (respline);
          return FTPRESTFAIL;
        }
#endif
      xfree (respline);
      return FTPRETRINT;
    }
  else if (opt.warc_filename != NULL)
    {
      if (expected_bytes == rd_size || warc_context->is_list)
        {
          warc_context->written_resource = true;
          warc_context->hstatp->statcode = 100 * (respline[0] - '0') + 10 * (respline[1] - '0') + (respline[2] - '0');
          warc_context->hstatp->message = xstrdup (respline+3);
        }
      else
        {
          if (write_control_message_event ("Incomplete data received\r\n", -1,
                                           warc_context->ccon_fp) < 0)
            return WARC_TMP_FWRITEERR;
        }
    }

  xfree (respline);

  if (res == -1)
    {
      /* What now?  The data connection was erroneous, whereas the
         response says everything is OK.  We shall play it safe.  */
      return FTPRETRINT;
    }

  if (!(cmd & LEAVE_PENDING))
    {
      /* Closing the socket is faster than sending 'QUIT' and the
         effect is the same.  */
      err_tmp = close_sock (csock, 0, con, warc_context->ccon_fp, RETROK);
      if (err_tmp != RETROK)
        return err_tmp;
    }
  /* If it was a listing, and opt.server_response is true,
     print it out.  */
  if (con->cmd & DO_LIST)
    {
      if (opt.server_response)
        {
/* 2005-02-25 SMS.
   Much of this work may already have been done, but repeating it should
   do no damage beyond wasting time.
*/
/* On VMS, alter the name as required. */
#ifdef __VMS
      char *targ;

      targ = ods_conform (con->target);
      if (targ != con->target)
        {
          xfree (con->target);
          con->target = targ;
        }
#endif /* def __VMS */

      mkalldirs (con->target);
      fp = fopen (con->target, "r");
      if (!fp)
        logprintf (LOG_ALWAYS, "%s: %s\n", con->target, strerror (errno));
      else
        {
          char *line = NULL;
          size_t bufsize = 0;
          ssize_t len;

          /* The lines are being read with getline because of
             no-buffering on opt.lfile.  */
          while ((len = getline (&line, &bufsize, fp)) > 0)
            {
              while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                line[--len] = '\0';
              logprintf (LOG_ALWAYS, "%s\n",
                         quotearg_style (escape_quoting_style, line));
            }
          xfree (line);
          fclose (fp);
        }
        } /* server_response */

      /* 2013-10-17 Andrea Urbani (matfanjol)
         < __LIST_A_EXPLANATION__ >
          After the SYST command, looks if it knows that system.
          If yes, wget will force the use of "LIST" or "LIST -a".
          If no, wget will try, only the first time of each session, before the
          "LIST -a" command and after the "LIST".
          If "LIST -a" works and returns more or equal data of the "LIST",
          "LIST -a" will be the standard list command for all the session.
          If "LIST -a" fails or returns less data than "LIST" (think on the case
          of an existing file called "-a"), "LIST" will be the standard list
          command for all the session.
          ("LIST -a" is used to get also the hidden files)

          */
      if (!(con->st & LIST_AFTER_LIST_A_CHECK_DONE))
        {
          /* We still have to check "LIST" after the first "LIST -a" to see
             if with "LIST" we get more data than "LIST -a", that means
             "LIST -a" returned files/folders with "-a" name. */
          if (con->st & AVOID_LIST_A)
            {
              /* LIST was used in this cycle.
                 Let's see the result. */
              if (rd_size > previous_rd_size)
                {
                  /* LIST returns more data than "LIST -a".
                     "LIST" is the official command to use. */
                  con->st |= LIST_AFTER_LIST_A_CHECK_DONE;
                  DEBUGP (("LIST returned more data than \"LIST -a\": "
                           "I will use \"LIST\" as standard list command\n"));
                }
              else if (previous_rd_size > rd_size)
                {
                  /* "LIST -a" returned more data then LIST.
                     "LIST -a" is the official command to use. */
                  con->st |= LIST_AFTER_LIST_A_CHECK_DONE;
                  con->st |= AVOID_LIST;
                  con->st &= ~AVOID_LIST_A;
                  /* Sorry, please, download again the "LIST -a"... */
                  try_again = true;
                  DEBUGP (("LIST returned less data than \"LIST -a\": I will "
                           "use \"LIST -a\" as standard list command\n"));
                }
              else
                {
                  /* LIST and "LIST -a" return the same data. */
                  if (rd_size == 0)
                    {
                      /* Same empty data. We will check both again because
                         we cannot check if "LIST -a" has returned an empty
                         folder instead of a folder content. */
                      con->st &= ~AVOID_LIST_A;
                    }
                  else
                    {
                      /* Same data, so, better to take "LIST -a" that
                         shows also hidden files/folders (when present) */
                      con->st |= LIST_AFTER_LIST_A_CHECK_DONE;
                      con->st |= AVOID_LIST;
                      con->st &= ~AVOID_LIST_A;
                      DEBUGP (("LIST returned the same amount of data of "
                               "\"LIST -a\": I will use \"LIST -a\" as standard "
                               "list command\n"));
                    }
                }
            }
          else
            {
              /* In this cycle "LIST -a" should being used. Is it true? */
              if (list_a_used)
                {
                  /* Yes, it is.
                     OK, let's save the amount of data and try again
                     with LIST */
                  previous_rd_size = rd_size;
                  try_again = true;
                  con->st |= AVOID_LIST_A;
                }
              else
                {
                  /* No: something happens and LIST was used.
                     This means "LIST -a" raises an error. */
                  con->st |= LIST_AFTER_LIST_A_CHECK_DONE;
                  con->st |= AVOID_LIST_A;
                  DEBUGP (("\"LIST -a\" failed: I will use \"LIST\" "
                           "as standard list command\n"));
                }
            }
        }
    }
  } while (try_again);
  return RETRFINISHED;

exit_error:

  /* If fp is a regular file, close and try to remove it */
  if (fp && (!output_stream || con->cmd & DO_LIST))
    fclose (fp);
  return err;
}

/* A one-file FTP loop.  This is the part where FTP retrieval is
   retried, and retried, and retried, and...

   This loop either gets commands from con, or (if ON_YOUR_OWN is
   set), makes them up to retrieve the file given by the URL.  */
static uerr_t
ftp_loop_internal (struct url *u, struct url *original_url, struct fileinfo *f,
                   ccon *con, char **local_file, bool force_full_retrieve,
                   struct warc_context *warc_context, struct hash_table *blacklist,
                   struct luahooks_url **luahooks_url)
{
  int count, orig_lp;
  wgint restval, len = 0, qtyread = 0;
  char *tms, *locf;
  const char *tmrate = NULL;
  uerr_t err, err_tmp;
  struct stat st;
  struct luahooks_url *luahooks_local_url;

  /* Declare WARC variables. */
  bool warc_enabled = (opt.warc_filename != NULL);
  wgint last_expected_bytes = 0;

  /* Get the target, and set the name for the message accordingly. */
  if ((f == NULL) && (con->target))
    {
      /* Explicit file (like ".listing"). */
      locf = con->target;
    }
  else
    {
      /* URL-derived file.  Consider "-O file" name. */
      xfree (con->target);
      con->target = url_file_name (opt.trustservernames || !original_url ? u : original_url, NULL);
      if (!opt.output_document)
        locf = con->target;
      else
        locf = opt.output_document;
    }

  /* If the output_document was given, then this check was already done and
     the file didn't exist. Hence the !opt.output_document */

  /* If we receive .listing file it is necessary to determine system type of the ftp
     server even if opn.noclobber is given. Thus we must ignore opt.noclobber in
     order to establish connection with the server and get system type. */
  if (opt.noclobber && !opt.output_document && file_exists_p (con->target, NULL)
      && !((con->cmd & DO_LIST) && !(con->cmd & DO_RETR)))
    {
      logprintf (LOG_VERBOSE,
                 _("File %s already there; not retrieving.\n"), quote (con->target));
      /* If the file is there, we suppose it's retrieved OK.  */
      return RETROK;
    }

  /* Remove it if it's a link.  */
  remove_link (con->target);

  count = 0;

  if (con->st & ON_YOUR_OWN)
    con->st = ON_YOUR_OWN;

  orig_lp = con->cmd & LEAVE_PENDING ? 1 : 0;

  /* THE loop.  */
  do
    {
      /* Increment the pass counter.  */
      ++count;
      sleep_between_retrievals (count);
      if (con->st & ON_YOUR_OWN)
        {
          con->cmd = 0;
          con->cmd |= (DO_RETR | LEAVE_PENDING);
          if (con->csock != -1)
            con->cmd &= ~ (DO_LOGIN | DO_CWD);
          else
            con->cmd |= (DO_LOGIN | DO_CWD);
        }
      else /* not on your own */
        {
          if (con->csock != -1)
            con->cmd &= ~DO_LOGIN;
          else
            con->cmd |= DO_LOGIN;
          if (con->st & DONE_CWD)
            con->cmd &= ~DO_CWD;
          else
            con->cmd |= DO_CWD;
        }

      /* Decide whether or not to restart.  */
      if (con->cmd & DO_LIST)
        restval = 0;
      else if (force_full_retrieve)
        restval = 0;
      else if (opt.start_pos >= 0)
        restval = opt.start_pos;
      else if (opt.always_rest
          && stat (locf, &st) == 0
          && S_ISREG (st.st_mode))
        /* When -c is used, continue from on-disk size.  (Can't use
           hstat.len even if count>1 because we don't want a failed
           first attempt to clobber existing data.)  */
        restval = st.st_size;
      else if (count > 1)
        restval = qtyread;          /* start where the previous run left off */
      else
        restval = 0;

      /* Get the current time string.  */
      tms = datetime_str (time (NULL));
      /* Print fetch message, if opt.verbose.  */
      if (opt.verbose)
        {
          char *hurl = url_string (u, URL_AUTH_HIDE_PASSWD);
          char tmp[256];
          strcpy (tmp, "        ");
          if (count > 1)
            sprintf (tmp, _("(try:%2d)"), count);
          logprintf (LOG_VERBOSE, "--%s--  %s\n  %s => %s\n",
                     tms, hurl, tmp, quote (locf));
#ifdef WINDOWS
          ws_changetitle (hurl);
#endif
          xfree (hurl);
        }
      /* Send getftp the proper length, if fileinfo was provided.  */
      if (f && f->type != FT_SYMLINK)
        len = f->size;
      else
        len = 0;

      warc_context->fileinfo = f;

      /* If we are working on a WARC record, getftp should also write
         to the warc_context->fp file. */
      err = getftp (u, original_url, len, &qtyread, restval, con, count,
                    &last_expected_bytes, warc_context);

      if (con->csock == -1)
        con->st &= ~DONE_CWD;
      else
        con->st |= DONE_CWD;

      if (opt.warc_filename)
        {
          luahook_action_t action = luahooks_httploop_result_ftp (
                    warc_context->url, err, warc_context->hstatp);
          switch (action)
            {
              case LUAHOOK_NOTHING:
                break;
              case LUAHOOK_CONTINUE:
                continue;
              case LUAHOOK_EXIT:
                return err;
              case LUAHOOK_ABORT:
                abort ();
            }

          if (luahooks_url != NULL)
            {
              luahooks_local_url = luahooks_get_urls_ftp (con->target, warc_context->url->url);

              if (luahooks_local_url != NULL)
                {
                  /* Add the returned URLs to the blacklist under a special
                     "luahook" value. */
                  struct luahooks_url *lh_url = luahooks_local_url;
                  while (lh_url != NULL)
                    {
                      if (!hash_table_contains (blacklist, lh_url->url))
                        hash_table_put (blacklist, xstrdup (lh_url->url), "luahook");
                      lh_url = lh_url->next;
                    }

                  /* Set the new found URLs, or append these. */
                  if (*luahooks_url == NULL)
                    *luahooks_url = luahooks_local_url;
                  else
                    {
                      lh_url = *luahooks_url;
                      while (lh_url->next != NULL)
                        lh_url = lh_url->next;
                      lh_url->next = luahooks_local_url;
                    }
                }
            }
        }

      switch (err)
        {
        case HOSTERR: case CONIMPOSSIBLE: case FWRITEERR: case FOPENERR:
        case FTPNSFOD: case FTPLOGINC: case FTPNOPASV: case FTPNOAUTH: case FTPNOPBSZ: case FTPNOPROT:
        case UNLINKERR: case WARC_TMP_FWRITEERR: case CONSSLERR: case CONTNOTSUPPORTED:
        case VERIFCERTERR:
#ifdef HAVE_SSL
          if (err == FTPNOAUTH)
            logputs (LOG_NOTQUIET, "Server does not support AUTH TLS.\n");
          if (opt.ftps_implicit)
            logputs (LOG_NOTQUIET, "Server does not like implicit FTPS connections.\n");
#endif
          /* Fatal errors, give up.  */
          return err;
        case CONSOCKERR: case CONERROR: case FTPSRVERR: case FTPRERR:
        case WRITEFAILED: case FTPUNKNOWNTYPE: case FTPSYSERR:
        case FTPPORTERR: case FTPLOGREFUSED: case FTPINVPASV:
        case FOPEN_EXCL_ERR:
          printwhat (count, opt.ntry);
          /* non-fatal errors */
          if (err == FOPEN_EXCL_ERR)
            {
              /* Re-determine the file name. */
              xfree (con->target);
              con->target = url_file_name (u, NULL);
              locf = con->target;
            }
          continue;
        case FTPRETRINT:
          /* If the control connection was closed, the retrieval
             will be considered OK if f->size == len.  */
          if (!f || qtyread != f->size)
            {
              printwhat (count, opt.ntry);
              continue;
            }
          break;
        case RETRFINISHED:
          /* Great!  */
          break;
        default:
          /* Not as great.  */
          abort ();
        }
      tms = datetime_str (time (NULL));
      if (!opt.spider)
        tmrate = retr_rate (qtyread - restval, con->dltime);

      /* If we get out of the switch above without continue'ing, we've
         successfully downloaded a file.  Remember this fact. */
      downloaded_file (FILE_DOWNLOADED_NORMALLY, locf);

      if (con->st & ON_YOUR_OWN)
        {
          err_tmp = close_sock (con->csock, 0, con, warc_context->ccon_fp, RETROK);
          if (err_tmp != RETROK)
            return err_tmp;
        }
      if (!opt.spider)
        {
          bool write_to_stdout = (opt.output_document && HYPHENP (opt.output_document));

          logprintf (LOG_VERBOSE,
                     write_to_stdout
                     ? _("%s (%s) - written to stdout %s[%s]\n\n")
                     : _("%s (%s) - %s saved [%s]\n\n"),
                     tms, tmrate,
                     write_to_stdout ? "" : quote (locf),
                     number_to_static_string (qtyread));
        }
      if (!opt.verbose && !opt.quiet)
        {
          /* Need to hide the password from the URL.  The `if' is here
             so that we don't do the needless allocation every
             time. */
          char *hurl = url_string (u, URL_AUTH_HIDE_PASSWD);
          logprintf (LOG_NONVERBOSE, "%s URL: %s [%s] -> \"%s\" [%d]\n",
                     tms, hurl, number_to_static_string (qtyread), locf, count);
          xfree (hurl);
        }

      if (con->cmd & DO_LIST)
        /* This is a directory listing file. */
        {
          /* In case of writing to a WARC, the lists are also counted
             in the total size. */
          if (!opt.remove_listing || opt.warc_filename)
            /* --dont-remove-listing was specified, so do count this towards the
               number of bytes and files downloaded. */
            {
              total_downloaded_bytes += (qtyread - restval);
              numurls++;
            }

          /* Deletion of listing files is not controlled by --delete-after, but
             by the more specific option --dont-remove-listing, and the code
             to do this deletion is in another function. */
        }
      else if (!opt.spider)
        /* This is not a directory listing file. */
        {
          /* Unlike directory listing files, don't pretend normal files weren't
             downloaded if they're going to be deleted.  People seeding proxies,
             for instance, may want to know how many bytes and files they've
             downloaded through it. */
          total_downloaded_bytes += (qtyread - restval);
          numurls++;

          if (opt.delete_after && !input_file_url (opt.input_filename))
            {
              DEBUGP (("\
Removing file due to --delete-after in ftp_loop_internal():\n"));
              logprintf (LOG_VERBOSE, _("Removing %s.\n"), locf);
              if (unlink (locf))
                logprintf (LOG_NOTQUIET, "unlink: %s\n", strerror (errno));
            }
        }

      /* Restore the original leave-pendingness.  */
      if (orig_lp)
        con->cmd |= LEAVE_PENDING;
      else
        con->cmd &= ~LEAVE_PENDING;

      if (local_file)
        *local_file = xstrdup (locf);

      return RETROK;
    } while (!opt.ntry || (count < opt.ntry));

  if (con->csock != -1 && (con->st & ON_YOUR_OWN))
    {
      err_tmp = close_sock (con->csock, 0, con, warc_context->ccon_fp, RETROK);
      if (err_tmp != RETROK)
        return err_tmp;
    }

  /* The WARC records are not written out here, but the next time this
     function is called, or finally at the end of ftp_loop. This way any
     information that should go into the control conversation record can
     still be captured up to the very end of the retrieval process. */

  return TRYLIMEXC;
}

/* Return the directory listing in a reusable format.  The directory
   is specified in u->dir.  */
static uerr_t
ftp_get_listing (struct url *u, struct url *original_url, ccon *con,
                 struct fileinfo **f, struct warc_context *warc_context,
                 struct hash_table *blacklist, struct luahooks_url **luahooks_url)
{
  uerr_t err, err_tmp;
  char *uf;                     /* url file name */
  char *lf;                     /* list file name */
  char *old_target = con->target;

  con->st &= ~ON_YOUR_OWN;
  con->cmd |= (DO_LIST | LEAVE_PENDING);
  con->cmd &= ~DO_RETR;

  /* Find the listing file name.  We do it by taking the file name of
     the URL and replacing the last component with the listing file
     name.  */
  uf = url_file_name (u, NULL);
  lf = file_merge (uf, LIST_FILENAME);
  xfree (uf);
  DEBUGP ((_("Using %s as listing tmp file.\n"), quote (lf)));

  con->target = xstrdup (lf);
  xfree (lf);
  err = ftp_loop_internal (u, original_url, NULL, con, NULL, false,
                           warc_context, blacklist, luahooks_url);
  lf = xstrdup (con->target);
  xfree (con->target);
  con->target = old_target;

  if (err == RETROK)
    {
      *f = ftp_parse_ls (lf, con->rs);
      if (opt.remove_listing)
        {
          if (unlink (lf))
            logprintf (LOG_NOTQUIET, "unlink: %s\n", strerror (errno));
          else
            logprintf (LOG_VERBOSE, _("Removed %s.\n"), quote (lf));
        }
    }
  else
    *f = NULL;
  xfree (lf);
  con->cmd &= ~DO_LIST;

  /* FTP listings are retrieved here, mainly. A HTML-ized version of the
     listing is created and written to the temporary file for later
     writing to the WARC file if wanted. */
  if (opt.warc_ftp_html_conversion && warc_context->written_resource)
    {
      err_tmp = ftp_index (NULL, u, *f, warc_context);
      if (err_tmp != FTPOK)
        return err_tmp;
    }

  return err;
}

static uerr_t ftp_retrieve_dirs (struct url *, struct url *,
                                 struct fileinfo *, ccon *,
                                 struct warc_context *,
                                 struct hash_table *,
                                 struct luahooks_url **);
static uerr_t ftp_retrieve_glob (struct url *, struct url *, ccon *, int,
                                 struct warc_context *,
                                 struct hash_table *,
                                 struct luahooks_url **);
static struct fileinfo *delelement (struct fileinfo **, struct fileinfo **);

/* Retrieve a list of files given in struct fileinfo linked list.  If
   a file is a symbolic link, do not retrieve it, but rather try to
   set up a similar link on the local disk, if the symlinks are
   supported.

   If opt.recursive is set, after all files have been retrieved,
   ftp_retrieve_dirs will be called to retrieve the directories.  */
static uerr_t
ftp_retrieve_list (struct url *u, struct url *original_url,
                   struct fileinfo *f, ccon *con,
                   struct warc_context *warc_context,
                   struct hash_table *blacklist,
                   struct luahooks_url **luahooks_url)
{
  static int depth = 0;
  uerr_t err;
  struct fileinfo *orig;
  wgint local_size;
  time_t tml;
  bool dlthis; /* Download this (file). */
  const char *actual_target = NULL;
  bool force_full_retrieve = false;

  /* Increase the depth.  */
  ++depth;
  if (opt.reclevel != INFINITE_RECURSION && depth > opt.reclevel)
    {
      DEBUGP ((_("Recursion depth %d exceeded max. depth %d.\n"),
               depth, opt.reclevel));
      --depth;
      return RECLEVELEXC;
    }

  assert (f != NULL);
  orig = f;

  con->st &= ~ON_YOUR_OWN;
  if (!(con->st & DONE_CWD))
    con->cmd |= DO_CWD;
  else
    con->cmd &= ~DO_CWD;
  con->cmd |= (DO_RETR | LEAVE_PENDING);

  if (con->csock < 0)
    con->cmd |= DO_LOGIN;
  else
    con->cmd &= ~DO_LOGIN;

  err = RETROK;                 /* in case it's not used */

  while (f)
    {
      char *old_target, *ofile;

      if (opt.quota && total_downloaded_bytes > opt.quota)
        {
          --depth;
          return QUOTEXC;
        }
      old_target = con->target;

      ofile = xstrdup (u->file);
      url_set_file (u, f->name);

      con->target = url_file_name (u, NULL);
      err = RETROK;

      dlthis = true;
      if (opt.timestamping && f->type == FT_PLAINFILE)
        {
          struct stat st;
          /* If conversion of HTML files retrieved via FTP is ever implemented,
             we'll need to stat() <file>.orig here when -K has been specified.
             I'm not implementing it now since files on an FTP server are much
             more likely than files on an HTTP server to legitimately have a
             .orig suffix. */
          if (!stat (con->target, &st))
            {
              bool eq_size;
              bool cor_val;
              /* Else, get it from the file.  */
              local_size = st.st_size;
              tml = st.st_mtime;
#ifdef WINDOWS
              /* Modification time granularity is 2 seconds for Windows, so
                 increase local time by 1 second for later comparison. */
              tml++;
#endif
              /* Compare file sizes only for servers that tell us correct
                 values. Assume sizes being equal for servers that lie
                 about file size.  */
              cor_val = (con->rs == ST_UNIX || con->rs == ST_WINNT);
              eq_size = cor_val ? (local_size == f->size) : true;
              if (f->tstamp <= tml && eq_size)
                {
                  /* Remote file is older, file sizes can be compared and
                     are both equal. */
                  logprintf (LOG_VERBOSE, _("\
Remote file no newer than local file %s -- not retrieving.\n"), quote (con->target));
                  dlthis = false;
                }
              else if (f->tstamp > tml)
                {
                  /* Remote file is newer */
                  force_full_retrieve = true;
                  logprintf (LOG_VERBOSE, _("\
Remote file is newer than local file %s -- retrieving.\n\n"),
                             quote (con->target));
                }
              else
                {
                  /* Sizes do not match */
                  logprintf (LOG_VERBOSE, _("\
The sizes do not match (local %s) -- retrieving.\n\n"),
                             number_to_static_string (local_size));
                }
            }
        }       /* opt.timestamping && f->type == FT_PLAINFILE */
      switch (f->type)
        {
        case FT_SYMLINK:
          /* If opt.retr_symlinks is defined, we treat symlinks as
             if they were normal files.  There is currently no way
             to distinguish whether they might be directories, and
             follow them.  */
          if (!opt.retr_symlinks)
            {
#ifdef HAVE_SYMLINK
              if (!f->linkto)
                logputs (LOG_NOTQUIET,
                         _("Invalid name of the symlink, skipping.\n"));
              else
                {
                  struct stat st;
                  /* Check whether we already have the correct
                     symbolic link.  */
                  int rc = lstat (con->target, &st);
                  if (rc == 0)
                    {
                      size_t len = strlen (f->linkto) + 1;
                      if (S_ISLNK (st.st_mode))
                        {
                          char buf[1024], *link_target;
                          size_t n;
                          bool res;

                          if (len < sizeof (buf))
                            link_target = buf;
                          else
                            link_target = xmalloc (len);

                          n = readlink (con->target, link_target, len);
                          res = (n == len - 1) && (memcmp (link_target, f->linkto, n) == 0);

                          if (link_target != buf)
                            xfree (link_target);

                          if (res)
                            {
                              logprintf (LOG_VERBOSE, _("\
Already have correct symlink %s -> %s\n\n"),
                                         quote_n (0, con->target),
                                         quote_n (1, f->linkto));
                              dlthis = false;
                              break;
                            }
                        }
                    }
                  logprintf (LOG_VERBOSE, _("Creating symlink %s -> %s\n"),
                             quote_n (0, con->target), quote_n (1, f->linkto));
                  /* Unlink before creating symlink!  */
                  unlink (con->target);
                  if (symlink (f->linkto, con->target) == -1)
                    logprintf (LOG_NOTQUIET, "symlink: %s\n", strerror (errno));
                  logputs (LOG_VERBOSE, "\n");
                } /* have f->linkto */
#else  /* not HAVE_SYMLINK */
              logprintf (LOG_NOTQUIET,
                         _("Symlinks not supported, skipping symlink %s.\n"),
                         quote (con->target));
#endif /* not HAVE_SYMLINK */
            }
          else                /* opt.retr_symlinks */
            {
              if (dlthis)
                {
                  err = ftp_loop_internal (u, original_url, f, con, NULL,
                                           force_full_retrieve, warc_context,
                                           blacklist, luahooks_url);
                }
            } /* opt.retr_symlinks */
          break;
        case FT_DIRECTORY:
          if (!opt.recursive)
            logprintf (LOG_NOTQUIET, _("Skipping directory %s.\n"),
                       quote (f->name));
          break;
        case FT_PLAINFILE:
          /* Call the retrieve loop.  */
          if (dlthis)
            {
              err = ftp_loop_internal (u, original_url, f, con, NULL,
                                       force_full_retrieve, warc_context,
                                       blacklist, luahooks_url);
            }
          break;
        case FT_UNKNOWN:
        default:
          logprintf (LOG_NOTQUIET, _("%s: unknown/unsupported file type.\n"),
                     quote (f->name));
          break;
        }       /* switch */


      /* 2004-12-15 SMS.
       * Set permissions _before_ setting the times, as setting the
       * permissions changes the modified-time, at least on VMS.
       * Also, use the opt.output_document name here, too, as
       * appropriate.  (Do the test once, and save the result.)
       */

      set_local_file (&actual_target, con->target);

      /* If downloading a plain file, and the user requested it, then
         set valid (non-zero) permissions. */
      if (dlthis && (actual_target != NULL) &&
       (f->type == FT_PLAINFILE) && opt.preserve_perm)
        {
          if (f->perms)
            {
              if (chmod (actual_target, f->perms))
                logprintf (LOG_NOTQUIET,
                           _("Failed to set permissions for %s.\n"),
                           actual_target);
            }
          else
            DEBUGP (("Unrecognized permissions for %s.\n", actual_target));
        }

      /* Set the time-stamp information to the local file.  Symlinks
         are not to be stamped because it sets the stamp on the
         original.  :( */
      if (actual_target != NULL)
        {
          if (opt.useservertimestamps
              && !(f->type == FT_SYMLINK && !opt.retr_symlinks)
              && f->tstamp != -1
              && dlthis
              && file_exists_p (con->target, NULL))
            {
              touch (actual_target, f->tstamp);
            }
          else if (f->tstamp == -1)
            logprintf (LOG_NOTQUIET, _("%s: corrupt time-stamp.\n"),
                       actual_target);
        }

      xfree (con->target);
      con->target = old_target;

      url_set_file (u, ofile);
      xfree (ofile);

      /* Break on fatals.  */
      if (err == QUOTEXC || err == HOSTERR || err == FWRITEERR
          || err == WARC_ERR || err == WARC_TMP_FOPENERR
          || err == WARC_TMP_FWRITEERR)
        break;
      con->cmd &= ~ (DO_CWD | DO_LOGIN);
      f = f->next;
    }

  /* We do not want to call ftp_retrieve_dirs here */
  if (opt.recursive &&
      !(opt.reclevel != INFINITE_RECURSION && depth >= opt.reclevel))
    err = ftp_retrieve_dirs (u, original_url, orig, con, warc_context,
                             blacklist, luahooks_url);
  else if (opt.recursive)
    DEBUGP ((_("Will not retrieve dirs since depth is %d (max %d).\n"),
             depth, opt.reclevel));
  --depth;
  return err;
}

/* Retrieve the directories given in a file list.  This function works
   by simply going through the linked list and calling
   ftp_retrieve_glob on each directory entry.  The function knows
   about excluded directories.  */
static uerr_t
ftp_retrieve_dirs (struct url *u, struct url *original_url,
                   struct fileinfo *f, ccon *con,
                   struct warc_context *warc_context,
                   struct hash_table *blacklist,
                   struct luahooks_url **luahooks_url)
{
  char buf[1024];
  char *container = buf;
  int container_size = sizeof (buf);

  for (; f; f = f->next)
    {
      int size;
      char *odir, *newdir;

      if (opt.quota && total_downloaded_bytes > opt.quota)
        break;
      if (f->type != FT_DIRECTORY)
        continue;

      /* Allocate u->dir off stack, but reallocate only if a larger
         string is needed.  It's a pity there's no "realloca" for an
         item on the bottom of the stack.  */
      size = strlen (u->dir) + 1 + strlen (f->name) + 1;
      if (size > container_size)
        {
          if (container == buf)
            container = xmalloc (size);
          else
            container = xrealloc (container, size);

          container_size = size;
        }
      newdir = container;

      odir = u->dir;
      if (*odir == '\0'
          || (*odir == '/' && *(odir + 1) == '\0'))
        /* If ODIR is empty or just "/", simply append f->name to
           ODIR.  (In the former case, to preserve u->dir being
           relative; in the latter case, to avoid double slash.)  */
        sprintf (newdir, "%s%s", odir, f->name);
      else
        /* Else, use a separator. */
        sprintf (newdir, "%s/%s", odir, f->name);

      DEBUGP (("Composing new CWD relative to the initial directory.\n"));
      DEBUGP (("  odir = '%s'\n  f->name = '%s'\n  newdir = '%s'\n\n",
               odir, f->name, newdir));
      if (!accdir (newdir))
        {
          logprintf (LOG_VERBOSE, _("\
Not descending to %s as it is excluded/not-included.\n"),
                     quote (newdir));
          continue;
        }

      con->st &= ~DONE_CWD;

      odir = xstrdup (u->dir);  /* because url_set_dir will free
                                   u->dir. */
      url_set_dir (u, newdir);
      ftp_retrieve_glob (u, original_url, con, GLOB_GETALL, warc_context,
                         blacklist, luahooks_url);
      url_set_dir (u, odir);
      xfree (odir);

      /* Set the time-stamp?  */
    }

  if (container != buf)
    xfree (container);

  if (opt.quota && total_downloaded_bytes > opt.quota)
    return QUOTEXC;
  else
    return RETROK;
}

/* Return true if S has a leading '/'  or contains '../' */
static bool
has_insecure_name_p (const char *s)
{
  if (*s == '/')
    return true;

  if (strstr (s, "../") != 0)
    return true;

  return false;
}

/* Test if the file node is invalid. This can occur due to malformed or
 * maliciously crafted listing files being returned by the server.
 *
 * Currently, this function only tests if there are multiple entries in the
 * listing file by the same name. However this function can be expanded as more
 * such illegal listing formats are discovered. */
static bool
is_invalid_entry (struct fileinfo *f)
{
  struct fileinfo *cur = f;
  char *f_name = f->name;

  /* If the node we're currently checking has a duplicate later, we eliminate
   * the current node and leave the next one intact. */
  while (cur->next)
    {
      cur = cur->next;
      if (strcmp (f_name, cur->name) == 0)
          return true;
    }
  return false;
}

/* A near-top-level function to retrieve the files in a directory.
   The function calls ftp_get_listing, to get a linked list of files.
   Then it weeds out the file names that do not match the pattern.
   ftp_retrieve_list is called with this updated list as an argument.

   If the argument ACTION is GLOB_GETONE, just download the file (but
   first get the listing, so that the time-stamp is heeded); if it's
   GLOB_GLOBALL, use globbing; if it's GLOB_GETALL, download the whole
   directory.  */
static uerr_t
ftp_retrieve_glob (struct url *u, struct url *original_url,
                   ccon *con, int action, struct warc_context *warc_context,
                   struct hash_table *blacklist, struct luahooks_url **luahooks_url)
{
  struct fileinfo *f, *start;
  uerr_t res, err_tmp;
  bool lua_verdict;
  int num_checked = 0;
  int num_lua_skipped = 0;

  con->cmd |= LEAVE_PENDING;

  res = ftp_get_listing (u, original_url, con, &start, warc_context, blacklist,
                         luahooks_url);
  if (res != RETROK)
    return res;

  // Set the function used for glob matching.
  int (*matcher) (const char *, const char *, int)
    = opt.ignore_case ? fnmatch_nocase : fnmatch;

  // Set the function used to compare strings
#ifdef __VMS
  /* 2009-09-09 SMS.
   * Odd-ball compiler ("HP C V7.3-009 on OpenVMS Alpha V7.3-2")
   * bug causes spurious %CC-E-BADCONDIT complaint with this
   * "?:" statement.  (Different linkage attributes for strcmp()
   * and strcasecmp().)  Converting to "if" changes the
   * complaint to %CC-W-PTRMISMATCH on "cmp = strcmp;".  Adding
   * the senseless type cast clears the complaint, and looks
   * harmless.
   */
  int (*cmp) (const char *, const char *)
    = opt.ignore_case ? strcasecmp : (int (*)())strcmp;
#else /* def __VMS */
  int (*cmp) (const char *, const char *)
    = opt.ignore_case ? strcasecmp : strcmp;
#endif /* def __VMS [else] */

  f = start;
  while (f)
    {
      num_checked++;

      ftp_reject_reason rr = FTP_RR_SUCCESS;

      char *tmp_file = xstrdup (u->file);
      url_set_file (u, "");
      char *url = concat_strings (u->url, f->name, f->type == FT_DIRECTORY ? "/" : "", (char *) 0);;
      url_set_file (u, tmp_file);
      xfree (tmp_file);

      // Weed out files that do not confirm to the global rules given in
      // opt.accepts and opt.rejects
      if ((opt.accepts || opt.rejects) &&
          f->type != FT_DIRECTORY && !acceptable (f->name))
        {
          logprintf (LOG_VERBOSE, _("Rejecting %s.\n"),
                     quote (f->name));
          rr = FTP_RR_NOTACCEPTABLE;
        }

      // Identify and eliminate possibly harmful names or invalid entries.
      if (rr == FTP_RR_SUCCESS && has_insecure_name_p (f->name))
        {
          logprintf (LOG_VERBOSE, _("Rejecting %s (Insecure Name).\n"),
                     quote (f->name));
          rr = FTP_RR_INSECURENAME;
        }

      if (rr == FTP_RR_SUCCESS && is_invalid_entry (f))
        {
          logprintf (LOG_VERBOSE, _("Rejecting %s (Invalid Entry).\n"),
                     quote (f->name));
          rr = FTP_RR_INVALID;
        }

      if (rr == FTP_RR_SUCCESS && (opt.acceptregex || opt.rejectregex))
        {
          // accept_url() takes the full URL.
          if (!accept_url (url))
            {
              logprintf (LOG_VERBOSE, _ ("%s is excluded/not-included through regex.\n"), url);
              rr = FTP_RR_REGEX;
            }
        }

      /* Now weed out the files that do not match our globbing pattern.
         If we are dealing with a globbing pattern, that is.  */
      if (rr == FTP_RR_SUCCESS && *u->file)
        {
          if (action == GLOB_GLOBALL)
            {
              int matchres = matcher (u->file, f->name, 0);
              if (matchres == -1)
                {
                  logprintf (LOG_NOTQUIET, _("Error matching %s against %s: %s\n"),
                             u->file, quotearg_style (escape_quoting_style, f->name),
                             strerror (errno));
                  freefileinfo (start);
                  return RETRBADPATTERN;
                }
              if (matchres == FNM_NOMATCH)
                {
                  rr = FTP_RR_GLOB;
                }
            }
          else if (action == GLOB_GETONE)
            {
              if (0 != cmp(u->file, f->name))
                {
                  rr = FTP_RR_GLOB;
                }
            }
        }

      if (rr == FTP_RR_SUCCESS && blacklist != NULL
          && string_set_contains (blacklist, url)
          && strcmp (hash_table_get (blacklist, url), "luahook") == 0)
        {
          logprintf (LOG_VERBOSE, _("Rejecting %s (Blacklisted).\n"),
                     quote (f->name));
          rr = FTP_RR_BLACKLIST;
          num_lua_skipped++;
        }

      lua_verdict = luahooks_download_child_ftp (f, u, original_url, rr);

      if (lua_verdict)
        rr = FTP_RR_SUCCESS;
      else if (rr == FTP_RR_SUCCESS)
        {
          rr = FTP_RR_LUAHOOK;
          num_lua_skipped++;
        }

      if (rr != FTP_RR_SUCCESS)
        {
          f = delelement (&f, &start);
          xfree(url);
          continue;
        }

      if (!string_set_contains (blacklist, url))
        hash_table_put (blacklist, xstrdup (url), "wget");

      xfree(url);

      f = f->next;
    }

  /*
   * Now that preprocessing of the file listing is over, let's try to download
   * all the remaining files in our listing.
   */
  if (start)
    {
      /* Just get everything.  */
      res = ftp_retrieve_list (u, original_url, start, con, warc_context,
                               blacklist, luahooks_url);
    }
  else if (num_lua_skipped > 0)
    /* Without the Lua hook, the previous condition would have been true. */
    res = RETROK;
  else
    {
      if (action == GLOB_GLOBALL)
        {
          /* No luck.  */
          /* #### This message SUCKS.  We should see what was the
             reason that nothing was retrieved.  */
          logprintf (LOG_VERBOSE, _("No matches on pattern %s.\n"),
                     quote (u->file));
        }
      else if (action == GLOB_GETONE) /* GLOB_GETONE or GLOB_GETALL */
        {
          /* Let's try retrieving it anyway.  */
          con->st |= ON_YOUR_OWN;
          res = ftp_loop_internal (u, original_url, NULL, con, NULL, false,
                                   warc_context, blacklist, luahooks_url);
          return res;
        }

      /* If action == GLOB_GETALL, and the file list is empty, there's
         no point in trying to download anything or in complaining about
         it.  (An empty directory should not cause complaints.)
      */
    }
  freefileinfo (start);
  if (opt.quota && total_downloaded_bytes > opt.quota)
    return QUOTEXC;
  else
    return res;
}

/* The wrapper that calls an appropriate routine according to contents
   of URL.  Inherently, its capabilities are limited on what can be
   encoded into a URL.  */
uerr_t
ftp_loop (struct url *u, struct url *original_url, char **local_file, int *dt,
          struct url *proxy, bool recursive, bool glob, struct hash_table *blacklist,
          struct luahooks_url **luahooks_url)
{
  ccon con;                     /* FTP connection */
  uerr_t res, err_tmp;
  struct warc_context warc_context;

  bool blacklist_given = (blacklist != NULL);
  if (!blacklist_given)
    blacklist = make_string_hash_table (0);

  *dt = 0;

  xzero (con);
  xzero (warc_context);

  con.csock = -1;
  con.st = ON_YOUR_OWN;
  con.rs = ST_UNIX;
  con.id = NULL;
  con.proxy = proxy;

  /* If the file name is empty, the user probably wants a directory
     index.  We'll provide one, properly HTML-ized.  Unless
     opt.htmlify is 0, of course.  :-) */
  if (!*u->file && !recursive)
    {
      struct fileinfo *f;
      res = ftp_get_listing (u, original_url, &con, &f, &warc_context,
                             blacklist, luahooks_url);
      if (res == RETROK)
        {
          if (opt.htmlify && !opt.spider)
            {
              struct url *url_file = opt.trustservernames ? u : original_url;
              char *filename = (opt.output_document
                                ? xstrdup (opt.output_document)
                                : (con.target ? xstrdup (con.target)
                                   : url_file_name (url_file, NULL)));
              res = ftp_index (filename, u, f, NULL);
              if (res == FTPOK && opt.verbose)
                {
                  if (!opt.output_document)
                    {
                      struct stat st;
                      wgint sz;
                      if (stat (filename, &st) == 0)
                        sz = st.st_size;
                      else
                        sz = -1;
                      logprintf (LOG_NOTQUIET,
                                 _("Wrote HTML-ized index to %s [%s].\n"),
                                 quote (filename), number_to_static_string (sz));
                    }
                  else
                    logprintf (LOG_NOTQUIET,
                               _("Wrote HTML-ized index to %s.\n"),
                               quote (filename));
                }
              xfree (filename);
            }
          freefileinfo (f);
        }
    }
  else
    {
      bool ispattern = false;
      if (glob)
        {
          /* Treat the URL as a pattern if the file name part of the
             URL path contains wildcards.  (Don't check for u->file
             because it is unescaped and therefore doesn't leave users
             the option to escape literal '*' as %2A.)  */
          char *file_part = strrchr (u->path, '/');
          if (!file_part)
            file_part = u->path;
          ispattern = has_wildcards_p (file_part);
        }
      if (ispattern || recursive || opt.timestamping || opt.preserve_perm)
        {
          /* ftp_retrieve_glob is a catch-all function that gets called
             if we need globbing, time-stamping, recursion or preserve
             permissions.  Its third argument is just what we really need.  */
          res = ftp_retrieve_glob (u, original_url, &con,
                                   ispattern ? GLOB_GLOBALL : GLOB_GETONE,
                                   &warc_context, blacklist, luahooks_url);
        }
      else
        {
          res = ftp_loop_internal (u, original_url, NULL, &con, local_file,
                                   false, &warc_context, blacklist, luahooks_url);
        }
    }
  if (res == FTPOK)
    res = RETROK;
  if (res == RETROK)
    *dt |= RETROKF;

  /* If a connection was left, quench it.  */
  if (con.csock != -1)
    res = close_sock (con.csock, 0, &con, warc_context.ccon_fp, res);

  /* If data is not yet written to the WARC, write it. The last retrieved
     URL in ftp_loop is written in this way. */
  if (warc_context.fp != NULL || warc_context.ccon_fp != NULL)
    {
      warc_uuid_str (warc_context.record_id_uuid,
                     sizeof (warc_context.record_id_uuid));
      warc_uuid_str (warc_context.concurrent_to_uuid,
                     sizeof (warc_context.concurrent_to_uuid));
      if (warc_context.fp != NULL)
        {
          err_tmp = write_warc_resource (&warc_context, &con);
          if (err_tmp != RETROK)
            {
              res = err_tmp;
              goto exit;
            }
        }
      if (warc_context.ccon_fp != NULL)
        {
          err_tmp = write_warc_cconv (&warc_context, &con);
          if (err_tmp != RETROK)
            {
              res = err_tmp;
              goto exit;
            }
        }
    }

  if (warc_context.url != NULL)
    url_free (warc_context.url);
  if (warc_context.hstatp != NULL)
    {
      xfree (warc_context.hstatp->rderrmsg);
      xfree (warc_context.hstatp->message);
      xfree (warc_context.hstatp);
    }
  xzero (warc_context);

  xfree (con.id);
  xfree (con.target);

exit:
  if (!blacklist_given)
    string_set_free (blacklist);

  return res;
}

/* Delete an element from the fileinfo linked list.  Returns the
   address of the next element, or NULL if the list is exhausted.  It
   can modify the start of the list.  */
static struct fileinfo *
delelement (struct fileinfo **f, struct fileinfo **start)
{
  struct fileinfo *prev = (*f)->prev;
  struct fileinfo *next = (*f)->next;

  xfree ((*f)->name);
  xfree ((*f)->linkto);
  xfree (*f);

  if (next)
    next->prev = prev;
  if (prev)
    prev->next = next;
  else
    *start = next;
  return next;
}

/* Free the fileinfo linked list of files.  */
void
freefileinfo (struct fileinfo *f)
{
  while (f)
    {
      struct fileinfo *next = f->next;
      xfree (f->name);
      xfree (f->linkto);
      xfree (f);
      f = next;
    }
}
