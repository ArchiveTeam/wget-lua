/* SSL support via GnuTLS library.
   Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012 Free Software
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

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <sys/ioctl.h>

#include "utils.h"
#include "connect.h"
#include "url.h"
#include "ptimer.h"
#include "ssl.h"

#include <sys/fcntl.h>

#ifdef WIN32
# include "w32sock.h"
#endif

#include "host.h"

static int
key_type_to_gnutls_type (enum keyfile_type type)
{
  switch (type)
    {
    case keyfile_pem:
      return GNUTLS_X509_FMT_PEM;
    case keyfile_asn1:
      return GNUTLS_X509_FMT_DER;
    default:
      abort ();
    }
}

/* Note: some of the functions private to this file have names that
   begin with "wgnutls_" (e.g. wgnutls_read) so that they wouldn't be
   confused with actual gnutls functions -- such as the gnutls_read
   preprocessor macro.  */

static gnutls_certificate_credentials_t credentials;
bool
ssl_init (void)
{
  /* Becomes true if GnuTLS is initialized. */
  static bool ssl_initialized = false;

  /* GnuTLS should be initialized only once. */
  if (ssl_initialized)
    return true;

  const char *ca_directory;
  DIR *dir;

  gnutls_global_init ();
  gnutls_certificate_allocate_credentials (&credentials);
  gnutls_certificate_set_verify_flags(credentials,
                                      GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);

  ca_directory = opt.ca_directory ? opt.ca_directory : "/etc/ssl/certs";

  dir = opendir (ca_directory);
  if (dir == NULL)
    {
      if (opt.ca_directory && *opt.ca_directory)
        logprintf (LOG_NOTQUIET, _("ERROR: Cannot open directory %s.\n"),
                   opt.ca_directory);
    }
  else
    {
      struct dirent *dent;
      while ((dent = readdir (dir)) != NULL)
        {
          struct stat st;
          char *ca_file;
          asprintf (&ca_file, "%s/%s", ca_directory, dent->d_name);

          stat (ca_file, &st);

          if (S_ISREG (st.st_mode))
            gnutls_certificate_set_x509_trust_file (credentials, ca_file,
                                                    GNUTLS_X509_FMT_PEM);

          free (ca_file);
        }

      closedir (dir);
    }

  /* Use the private key from the cert file unless otherwise specified. */
  if (opt.cert_file && !opt.private_key)
    {
      opt.private_key = opt.cert_file;
      opt.private_key_type = opt.cert_type;
    }
  /* Use the cert from the private key file unless otherwise specified. */
  if (!opt.cert_file && opt.private_key)
    {
      opt.cert_file = opt.private_key;
      opt.cert_type = opt.private_key_type;
    }

  if (opt.cert_file && opt.private_key)
    {
      int type;
      if (opt.private_key_type != opt.cert_type)
	{
	  /* GnuTLS can't handle this */
	  logprintf (LOG_NOTQUIET, _("ERROR: GnuTLS requires the key and the \
cert to be of the same type.\n"));
	}

      type = key_type_to_gnutls_type (opt.private_key_type);

      gnutls_certificate_set_x509_key_file (credentials, opt.cert_file,
					    opt.private_key,
					    type);
    }

  if (opt.ca_cert)
    gnutls_certificate_set_x509_trust_file (credentials, opt.ca_cert,
                                            GNUTLS_X509_FMT_PEM);

  ssl_initialized = true;

  return true;
}

struct wgnutls_transport_context
{
  gnutls_session_t session;       /* GnuTLS session handle */
  int last_error;               /* last error returned by read/write/... */

  /* Since GnuTLS doesn't support the equivalent to recv(...,
     MSG_PEEK) or SSL_peek(), we have to do it ourselves.  Peeked data
     is stored to PEEKBUF, and wgnutls_read checks that buffer before
     actually reading.  */
  char peekbuf[512];
  int peeklen;
};

#ifndef MIN
# define MIN(i, j) ((i) <= (j) ? (i) : (j))
#endif


static int
wgnutls_read_timeout (int fd, char *buf, int bufsize, void *arg, double timeout)
{
#ifdef F_GETFL
  int flags = 0;
#endif
  int ret = 0;
  struct ptimer *timer = NULL;
  struct wgnutls_transport_context *ctx = arg;
  int timed_out = 0;

  if (timeout)
    {
#ifdef F_GETFL
      flags = fcntl (fd, F_GETFL, 0);
      if (flags < 0)
        return flags;
      if (fcntl (fd, F_SETFL, flags | O_NONBLOCK))
        return -1;
#else
      /* XXX: Assume it was blocking before.  */
      const int one = 1;
      if (ioctl (fd, FIONBIO, &one) < 0)
        return -1;
#endif

      timer = ptimer_new ();
      if (timer == NULL)
        return -1;
    }

  do
    {
      double next_timeout = 0;
      if (timeout)
        {
          next_timeout = timeout - ptimer_measure (timer);
          if (next_timeout < 0)
            break;
        }

      ret = GNUTLS_E_AGAIN;
      if (timeout == 0 || gnutls_record_check_pending (ctx->session)
          || select_fd (fd, next_timeout, WAIT_FOR_READ))
        {
          ret = gnutls_record_recv (ctx->session, buf, bufsize);
          timed_out = timeout && ptimer_measure (timer) >= timeout;
        }
    }
  while (ret == GNUTLS_E_INTERRUPTED || (ret == GNUTLS_E_AGAIN && !timed_out));

  if (timeout)
    {
      ptimer_destroy (timer);

#ifdef F_GETFL
      if (fcntl (fd, F_SETFL, flags) < 0)
        return -1;
#else
      const int zero = 0;
      if (ioctl (fd, FIONBIO, &zero) < 0)
        return -1;
#endif

      if (timed_out && ret == GNUTLS_E_AGAIN)
        errno = ETIMEDOUT;
    }

  return ret;
}

static int
wgnutls_read (int fd, char *buf, int bufsize, void *arg)
{
  int ret = 0;
  struct wgnutls_transport_context *ctx = arg;

  if (ctx->peeklen)
    {
      /* If we have any peek data, simply return that. */
      int copysize = MIN (bufsize, ctx->peeklen);
      memcpy (buf, ctx->peekbuf, copysize);
      ctx->peeklen -= copysize;
      if (ctx->peeklen != 0)
        memmove (ctx->peekbuf, ctx->peekbuf + copysize, ctx->peeklen);

      return copysize;
    }

  ret = wgnutls_read_timeout (fd, buf, bufsize, arg, opt.read_timeout);
  if (ret < 0)
    ctx->last_error = ret;

  return ret;
}

static int
wgnutls_write (int fd, char *buf, int bufsize, void *arg)
{
  int ret;
  struct wgnutls_transport_context *ctx = arg;
  do
    ret = gnutls_record_send (ctx->session, buf, bufsize);
  while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
  if (ret < 0)
    ctx->last_error = ret;
  return ret;
}

static int
wgnutls_poll (int fd, double timeout, int wait_for, void *arg)
{
  struct wgnutls_transport_context *ctx = arg;

  if (timeout)
    return ctx->peeklen || gnutls_record_check_pending (ctx->session)
      || select_fd (fd, timeout, wait_for);
  else
    return ctx->peeklen || gnutls_record_check_pending (ctx->session);
}

static int
wgnutls_peek (int fd, char *buf, int bufsize, void *arg)
{
  int read = 0;
  struct wgnutls_transport_context *ctx = arg;
  int offset = MIN (bufsize, ctx->peeklen);

  if (ctx->peeklen)
    {
      memcpy (buf, ctx->peekbuf, offset);
      return offset;
    }

  if (bufsize > sizeof ctx->peekbuf)
    bufsize = sizeof ctx->peekbuf;

  if (bufsize > offset)
    {
      if (opt.read_timeout && gnutls_record_check_pending (ctx->session) == 0
          && select_fd (fd, 0.0, WAIT_FOR_READ) <= 0)
        read = 0;
      else
        read = wgnutls_read_timeout (fd, buf + offset, bufsize - offset,
                                     ctx, opt.read_timeout);
      if (read < 0)
        {
          if (offset)
            read = 0;
          else
            return read;
        }

      if (read > 0)
        {
          memcpy (ctx->peekbuf + offset, buf + offset,
                  read);
          ctx->peeklen += read;
        }
    }

  return offset + read;
}

static const char *
wgnutls_errstr (int fd, void *arg)
{
  struct wgnutls_transport_context *ctx = arg;
  return gnutls_strerror (ctx->last_error);
}

static void
wgnutls_close (int fd, void *arg)
{
  struct wgnutls_transport_context *ctx = arg;
  /*gnutls_bye (ctx->session, GNUTLS_SHUT_RDWR);*/
  gnutls_deinit (ctx->session);
  xfree (ctx);
  close (fd);
}

/* gnutls_transport is the singleton that describes the SSL transport
   methods provided by this file.  */

static struct transport_implementation wgnutls_transport =
{
  wgnutls_read, wgnutls_write, wgnutls_poll,
  wgnutls_peek, wgnutls_errstr, wgnutls_close
};

bool
ssl_connect_wget (int fd, const char *hostname)
{
  struct wgnutls_transport_context *ctx;
  gnutls_session_t session;
  int err;
  gnutls_init (&session, GNUTLS_CLIENT);

  /* We set the server name but only if it's not an IP address. */
  if (! is_valid_ip_address (hostname))
    {
      gnutls_server_name_set (session, GNUTLS_NAME_DNS, hostname,
			      strlen (hostname));
    }

  gnutls_set_default_priority (session);
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, credentials);
#ifndef FD_TO_SOCKET
# define FD_TO_SOCKET(X) (X)
#endif
  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) FD_TO_SOCKET (fd));

  err = 0;
#if HAVE_GNUTLS_PRIORITY_SET_DIRECT
  switch (opt.secure_protocol)
    {
    case secure_protocol_auto:
      break;
    case secure_protocol_sslv2:
    case secure_protocol_sslv3:
      err = gnutls_priority_set_direct (session, "NORMAL:-VERS-TLS-ALL", NULL);
      break;
    case secure_protocol_tlsv1:
      err = gnutls_priority_set_direct (session, "NORMAL:-VERS-SSL3.0", NULL);
      break;
    default:
      abort ();
    }
#else
  int allowed_protocols[4] = {0, 0, 0, 0};
  switch (opt.secure_protocol)
    {
    case secure_protocol_auto:
      break;
    case secure_protocol_sslv2:
    case secure_protocol_sslv3:
      allowed_protocols[0] = GNUTLS_SSL3;
      err = gnutls_protocol_set_priority (session, allowed_protocols);
      break;

    case secure_protocol_tlsv1:
      allowed_protocols[0] = GNUTLS_TLS1_0;
      allowed_protocols[1] = GNUTLS_TLS1_1;
      allowed_protocols[2] = GNUTLS_TLS1_2;
      err = gnutls_protocol_set_priority (session, allowed_protocols);
      break;

    default:
      abort ();
    }
#endif

  if (err < 0)
    {
      logprintf (LOG_NOTQUIET, "GnuTLS: %s\n", gnutls_strerror (err));
      gnutls_deinit (session);
      return false;
    }

  err = gnutls_handshake (session);
  if (err < 0)
    {
      logprintf (LOG_NOTQUIET, "GnuTLS: %s\n", gnutls_strerror (err));
      gnutls_deinit (session);
      return false;
    }

  ctx = xnew0 (struct wgnutls_transport_context);
  ctx->session = session;
  fd_register_transport (fd, &wgnutls_transport, ctx);
  return true;
}

bool
ssl_check_certificate (int fd, const char *host)
{
  struct wgnutls_transport_context *ctx = fd_transport_context (fd);

  unsigned int status;
  int err;

  /* If the user has specified --no-check-cert, we still want to warn
     him about problems with the server's certificate.  */
  const char *severity = opt.check_cert ? _("ERROR") : _("WARNING");
  bool success = true;

  err = gnutls_certificate_verify_peers2 (ctx->session, &status);
  if (err < 0)
    {
      logprintf (LOG_NOTQUIET, _("%s: No certificate presented by %s.\n"),
                 severity, quotearg_style (escape_quoting_style, host));
      success = false;
      goto out;
    }

  if (status & GNUTLS_CERT_INVALID)
    {
      logprintf (LOG_NOTQUIET, _("%s: The certificate of %s is not trusted.\n"),
                 severity, quote (host));
      success = false;
    }
  if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
    {
      logprintf (LOG_NOTQUIET, _("%s: The certificate of %s hasn't got a known issuer.\n"),
                 severity, quote (host));
      success = false;
    }
  if (status & GNUTLS_CERT_REVOKED)
    {
      logprintf (LOG_NOTQUIET, _("%s: The certificate of %s has been revoked.\n"),
                 severity, quote (host));
      success = false;
    }

  if (gnutls_certificate_type_get (ctx->session) == GNUTLS_CRT_X509)
    {
      time_t now = time (NULL);
      gnutls_x509_crt_t cert;
      const gnutls_datum_t *cert_list;
      unsigned int cert_list_size;

      if ((err = gnutls_x509_crt_init (&cert)) < 0)
        {
          logprintf (LOG_NOTQUIET, _("Error initializing X509 certificate: %s\n"),
                     gnutls_strerror (err));
          success = false;
          goto out;
        }

      cert_list = gnutls_certificate_get_peers (ctx->session, &cert_list_size);
      if (!cert_list)
        {
          logprintf (LOG_NOTQUIET, _("No certificate found\n"));
          success = false;
          goto crt_deinit;
        }
      err = gnutls_x509_crt_import (cert, cert_list, GNUTLS_X509_FMT_DER);
      if (err < 0)
        {
          logprintf (LOG_NOTQUIET, _("Error parsing certificate: %s\n"),
                     gnutls_strerror (err));
          success = false;
          goto crt_deinit;
        }
      if (now < gnutls_x509_crt_get_activation_time (cert))
        {
          logprintf (LOG_NOTQUIET, _("The certificate has not yet been activated\n"));
          success = false;
        }
      if (now >= gnutls_x509_crt_get_expiration_time (cert))
        {
          logprintf (LOG_NOTQUIET, _("The certificate has expired\n"));
          success = false;
        }
      if (!gnutls_x509_crt_check_hostname (cert, host))
        {
          logprintf (LOG_NOTQUIET,
                     _("The certificate's owner does not match hostname %s\n"),
                     quote (host));
          success = false;
        }
 crt_deinit:
      gnutls_x509_crt_deinit (cert);
   }

 out:
  return opt.check_cert ? success : true;
}
