/* Metalink module.
   Copyright (C) 2015 Free Software Foundation, Inc.

This file is part of GNU Wget.

GNU Wget is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or (at
your option) any later version.

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
#ifdef HAVE_METALINK

#include "metalink.h"
#include "retr.h"
#include "exits.h"
#include "utils.h"
#include "sha256.h"
#include "xstrndup.h"
#include <errno.h>
#include <unistd.h> /* For unlink.  */
#include <metalink/metalink_parser.h>
#ifdef HAVE_GPGME
#include <gpgme.h>
#include <fcntl.h> /* For open and close.  */
#endif

#ifdef TESTING
#include "test.h"
#endif

/* Loop through all files in metalink structure and retrieve them.
   Returns RETROK if all files were downloaded.
   Returns last retrieval error (from retrieve_url) if some files
   could not be downloaded.  */
uerr_t
retrieve_from_metalink (const metalink_t* metalink)
{
  metalink_file_t **mfile_ptr;
  uerr_t last_retr_err = RETROK; /* Store last encountered retrieve error.  */

  FILE *_output_stream = output_stream;
  bool _output_stream_regular = output_stream_regular;
  char *_output_document = opt.output_document;

  DEBUGP (("Retrieving from Metalink\n"));

  /* No files to download.  */
  if (!metalink->files)
    return RETROK;

  if (opt.output_document)
    {
      /* We cannot support output_document as we need to compute checksum
         of downloaded file, and to remove it if the checksum is bad.  */
      logputs (LOG_NOTQUIET,
               _("-O not supported for metalink download. Ignoring.\n"));
    }

  for (mfile_ptr = metalink->files; *mfile_ptr; mfile_ptr++)
    {
      metalink_file_t *mfile = *mfile_ptr;
      metalink_resource_t **mres_ptr;
      char *filename = NULL;
      bool hash_ok = false;

      uerr_t retr_err = METALINK_MISSING_RESOURCE;

      /* -1 -> file should be rejected
         0 -> could not verify
         1 -> verified successfully  */
      char sig_status = 0;

      output_stream = NULL;

      DEBUGP (("Processing metalink file %s...\n", quote (mfile->name)));

      /* Resources are sorted by priority.  */
      for (mres_ptr = mfile->resources; *mres_ptr; mres_ptr++)
        {
          metalink_resource_t *mres = *mres_ptr;
          metalink_checksum_t **mchksum_ptr, *mchksum;
          struct iri *iri;
          struct url *url;
          int url_err;

          if (!RES_TYPE_SUPPORTED (mres->type))
            {
              logprintf (LOG_VERBOSE,
                         _("Resource type %s not supported, ignoring...\n"),
                         quote (mres->type));
              continue;
            }

          retr_err = METALINK_RETR_ERROR;

          /* If output_stream is not NULL, then we have failed on
             previous resource and are retrying. Thus, remove the file.  */
          if (output_stream)
            {
              fclose (output_stream);
              output_stream = NULL;
              if (unlink (filename))
                logprintf (LOG_NOTQUIET, "unlink: %s\n", strerror (errno));
              xfree (filename);
            }

          /* Parse our resource URL.  */
          iri = iri_new ();
          set_uri_encoding (iri, opt.locale, true);
          url = url_parse (mres->url, &url_err, iri, false);

          if (!url)
            {
              char *error = url_error (mres->url, url_err);
              logprintf (LOG_NOTQUIET, "%s: %s.\n", mres->url, error);
              xfree (error);
              inform_exit_status (URLERROR);
              iri_free (iri);
              continue;
            }
          else
            {
              /* Avoid recursive Metalink from HTTP headers.  */
              bool _metalink_http = opt.metalink_over_http;

              /* Assure proper local file name regardless of the URL
                 of particular Metalink resource.
                 To do that we create the local file here and put
                 it as output_stream. We restore the original configuration
                 after we are finished with the file.  */
              output_stream = unique_create (mfile->name, true, &filename);
              output_stream_regular = true;

              /* Store the real file name for displaying in messages.  */
              opt.output_document = filename;

              opt.metalink_over_http = false;
              DEBUGP (("Storing to %s\n", filename));
              retr_err = retrieve_url (url, mres->url, NULL, NULL,
                                       NULL, NULL, opt.recursive, iri, false);
              opt.metalink_over_http = _metalink_http;
            }
          url_free (url);
          iri_free (iri);

          if (retr_err == RETROK)
            {
              FILE *local_file;

              /* Check the digest.  */
              local_file = fopen (filename, "rb");
              if (!local_file)
                {
                  logprintf (LOG_NOTQUIET, _("Could not open downloaded file.\n"));
                  continue;
                }

              for (mchksum_ptr = mfile->checksums; *mchksum_ptr; mchksum_ptr++)
                {
                  char sha256[SHA256_DIGEST_SIZE];
                  char sha256_txt[2 * SHA256_DIGEST_SIZE + 1];

                  mchksum = *mchksum_ptr;

                  /* I have seen both variants...  */
                  if (strcasecmp (mchksum->type, "sha256")
                      && strcasecmp (mchksum->type, "sha-256"))
                    {
                      DEBUGP (("Ignoring unsupported checksum type %s.\n",
                               quote (mchksum->type)));
                      continue;
                    }

                  logprintf (LOG_VERBOSE, _("Computing checksum for %s\n"),
                             quote (mfile->name));

                  sha256_stream (local_file, sha256);
                  wg_hex_to_string (sha256_txt, sha256, SHA256_DIGEST_SIZE);
                  DEBUGP (("Declared hash: %s\n", mchksum->hash));
                  DEBUGP (("Computed hash: %s\n", sha256_txt));
                  if (!strcmp (sha256_txt, mchksum->hash))
                    {
                      logputs (LOG_VERBOSE,
                               _("Checksum matches.\n"));
                      hash_ok = true;
                    }
                  else
                    {
                      logprintf (LOG_NOTQUIET,
                                 _("Checksum mismatch for file %s.\n"),
                                 quote (mfile->name));
                      hash_ok = false;
                    }

                  /* Stop as soon as we checked the supported checksum.  */
                  break;
                } /* Iterate over available checksums.  */
              fclose (local_file);
              local_file = NULL;

              if (!hash_ok)
                continue;

              sig_status = 0; /* Not verified.  */

#ifdef HAVE_GPGME
              /* Check the crypto signature.

                 Note that the signtures from Metalink in XML will not be
                 parsed when using libmetalink version older than 0.1.3.
                 Metalink-over-HTTP is not affected by this problem.  */
              if (mfile->signature)
                {
                  metalink_signature_t *msig = mfile->signature;
                  gpgme_error_t gpgerr;
                  gpgme_ctx_t gpgctx;
                  gpgme_data_t gpgsigdata, gpgdata;
                  gpgme_verify_result_t gpgres;
                  gpgme_signature_t gpgsig;
                  gpgme_protocol_t gpgprot = GPGME_PROTOCOL_UNKNOWN;
                  int fd = -1;

                  /* Initialize the library - as name suggests.  */
                  gpgme_check_version (NULL);

                  /* Open data file.  */
                  fd = open (filename, O_RDONLY);
                  if (fd == -1)
                    {
                      logputs (LOG_NOTQUIET,
                               _("Could not open downloaded file for signature "
                                 "verification.\n"));
                      goto gpg_skip_verification;
                    }

                  /* Assign file descriptor to GPG data structure.  */
                  gpgerr = gpgme_data_new_from_fd (&gpgdata, fd);
                  if (gpgerr != GPG_ERR_NO_ERROR)
                    {
                      logprintf (LOG_NOTQUIET,
                                 "GPGME data_new_from_fd: %s\n",
                                 gpgme_strerror (gpgerr));
                      goto gpg_skip_verification;
                    }

                  /* Prepare new GPGME context.  */
                  gpgerr = gpgme_new (&gpgctx);
                  if (gpgerr != GPG_ERR_NO_ERROR)
                    {
                      logprintf (LOG_NOTQUIET,
                                 "GPGME new: %s\n",
                                 gpgme_strerror (gpgerr));
                      gpgme_data_release (gpgdata);
                      goto gpg_skip_verification;
                    }

                  DEBUGP (("Veryfying signature %s:\n%s\n",
                           quote (msig->mediatype),
                           msig->signature));

                  /* Check signature type.  */
                  if (!strcmp (msig->mediatype, "application/pgp-signature"))
                    gpgprot = GPGME_PROTOCOL_OpenPGP;
                  else /* Unsupported signature type.  */
                    {
                      gpgme_release (gpgctx);
                      gpgme_data_release (gpgdata);
                      goto gpg_skip_verification;
                    }

                  gpgerr = gpgme_set_protocol (gpgctx, gpgprot);
                  if (gpgerr != GPG_ERR_NO_ERROR)
                    {
                      logprintf (LOG_NOTQUIET,
                                 "GPGME set_protocol: %s\n",
                                 gpgme_strerror (gpgerr));
                      gpgme_release (gpgctx);
                      gpgme_data_release (gpgdata);
                      goto gpg_skip_verification;
                    }

                  /* Load the signature.  */
                  gpgerr = gpgme_data_new_from_mem (&gpgsigdata,
                                                    msig->signature,
                                                    strlen (msig->signature),
                                                    0);
                  if (gpgerr != GPG_ERR_NO_ERROR)
                    {
                      logprintf (LOG_NOTQUIET,
                                 _("GPGME data_new_from_mem: %s\n"),
                                 gpgme_strerror (gpgerr));
                      gpgme_release (gpgctx);
                      gpgme_data_release (gpgdata);
                      goto gpg_skip_verification;
                    }

                  /* Verify the signature.  */
                  gpgerr = gpgme_op_verify (gpgctx, gpgsigdata, gpgdata, NULL);
                  if (gpgerr != GPG_ERR_NO_ERROR)
                    {
                      logprintf (LOG_NOTQUIET,
                                 _("GPGME op_verify: %s\n"),
                                 gpgme_strerror (gpgerr));
                      gpgme_data_release (gpgsigdata);
                      gpgme_release (gpgctx);
                      gpgme_data_release (gpgdata);
                      goto gpg_skip_verification;
                    }

                  /* Check the results.  */
                  gpgres = gpgme_op_verify_result (gpgctx);
                  if (!gpgres)
                    {
                      logputs (LOG_NOTQUIET,
                               _("GPGME op_verify_result: NULL\n"));
                      gpgme_data_release (gpgsigdata);
                      gpgme_release (gpgctx);
                      gpgme_data_release (gpgdata);
                      goto gpg_skip_verification;
                    }

                  /* The list is null-terminated.  */
                  for (gpgsig = gpgres->signatures; gpgsig; gpgsig = gpgsig->next)
                    {
                      DEBUGP (("Checking signature 0x%p\n",
                               (void *) gpgsig));
                      DEBUGP (("Summary=0x%x Status=0x%x\n",
                               gpgsig->summary, gpgsig->status & 0xFFFF));

                      if (gpgsig->summary
                          & (GPGME_SIGSUM_VALID | GPGME_SIGSUM_GREEN))
                        {
                          logputs (LOG_VERBOSE,
                                   _("Signature validation suceeded.\n"));
                          sig_status = 1;
                          break;
                        }

                      if (gpgsig->summary & GPGME_SIGSUM_RED)
                        {
                          logputs (LOG_NOTQUIET,
                                   _("Invalid signature. Rejecting resource.\n"));
                          sig_status = -1;
                          break;
                        }

                      if (gpgsig->summary == 0
                          && (gpgsig->status & 0xFFFF) == GPG_ERR_NO_ERROR)
                        {
                          logputs (LOG_VERBOSE,
                                   _("Data matches signature, but signature "
                                     "is not trusted.\n"));
                        }

                      if ((gpgsig->status & 0xFFFF) != GPG_ERR_NO_ERROR)
                        {
                          logprintf (LOG_NOTQUIET,
                                     "GPGME: %s\n",
                                     gpgme_strerror (gpgsig->status & 0xFFFF));
                        }
                    }
                  gpgme_data_release (gpgsigdata);
                  gpgme_release (gpgctx);
                  gpgme_data_release (gpgdata);
gpg_skip_verification:
                  if (fd != -1)
                    close (fd);
                } /* endif (mfile->signature) */
#endif
              /* Stop if file was downloaded with success.  */
              if (sig_status >= 0)
                break;
            } /* endif RETR_OK.  */
        } /* Iterate over resources.  */

      if (retr_err != RETROK)
        {
          logprintf (LOG_VERBOSE, _("Failed to download %s. Skipping resource.\n"),
                     quote (mfile->name));
        }
      else if (!hash_ok)
        {
          retr_err = METALINK_CHKSUM_ERROR;
          logprintf (LOG_NOTQUIET,
                     _("File %s retrieved but checksum does not match. "
                       "\n"), quote (mfile->name));
        }
#ifdef HAVE_GPGME
        /* Signature will be only validated if hash check was successful.  */
      else if (sig_status < 0)
        {
          retr_err = METALINK_SIG_ERROR;
          logprintf (LOG_NOTQUIET,
                     _("File %s retrieved but signature does not match. "
                       "\n"), quote (mfile->name));
        }
#endif
      last_retr_err = retr_err == RETROK ? last_retr_err : retr_err;

      /* Remove the file if error encountered or if option specified.
         Note: the file has been downloaded using *_loop. Therefore, it
         is not necessary to keep the file for continuated download.  */
      if ((retr_err != RETROK || opt.delete_after)
           && filename != NULL && file_exists_p (filename))
        {
          logprintf (LOG_VERBOSE, _("Removing %s.\n"), quote (filename));
          if (unlink (filename))
            logprintf (LOG_NOTQUIET, "unlink: %s\n", strerror (errno));
        }
      if (output_stream)
        {
          fclose (output_stream);
          output_stream = NULL;
        }
      xfree (filename);
    } /* Iterate over files.  */

  /* Restore original values.  */
  opt.output_document = _output_document;
  output_stream_regular = _output_stream_regular;
  output_stream = _output_stream;

  return last_retr_err;
}

int metalink_res_cmp (const void* v1, const void* v2)
{
  const metalink_resource_t *res1 = *(metalink_resource_t **) v1,
                            *res2 = *(metalink_resource_t **) v2;
  if (res1->preference != res2->preference)
    return res2->preference - res1->preference;
  if (res1->priority != res2->priority)
    return res1->priority - res2->priority;
  if (opt.preferred_location)
    {
      int cmp = 0;
      if (res1->location &&
          !strcasecmp (opt.preferred_location, res1->location))
        cmp -= 1;
      if (res2->location &&
          !strcasecmp (opt.preferred_location, res2->location))
        cmp += 1;
      return cmp;
    }
  return 0;
}

/*
  Find value of given key. This is intended for Link header, but will
  work with any header that uses ';' as field separator and '=' as key-value
  separator.

  Link           = "Link" ":" #link-value
  link-value     = "<" URI-Reference ">" *( ";" link-param )
  link-param     = ( ( "rel" "=" relation-types )
                 | ( "anchor" "=" <"> URI-Reference <"> )
                 | ( "rev" "=" relation-types )
                 | ( "hreflang" "=" Language-Tag )
                 | ( "media" "=" ( MediaDesc | ( <"> MediaDesc <"> ) ) )
                 | ( "title" "=" quoted-string )
                 | ( "title*" "=" ext-value )
                 | ( "type" "=" ( media-type | quoted-mt ) )
                 | ( link-extension ) )
  link-extension = ( parmname [ "=" ( ptoken | quoted-string ) ] )
                 | ( ext-name-star "=" ext-value )
  ext-name-star  = parmname "*" ; reserved for RFC2231-profiled
                                ; extensions.  Whitespace NOT
                                ; allowed in between.
  ptoken         = 1*ptokenchar
  ptokenchar     = "!" | "#" | "$" | "%" | "&" | "'" | "("
                 | ")" | "*" | "+" | "-" | "." | "/" | DIGIT
                 | ":" | "<" | "=" | ">" | "?" | "@" | ALPHA
                 | "[" | "]" | "^" | "_" | "`" | "{" | "|"
                 | "}" | "~"
  media-type     = type-name "/" subtype-name
  quoted-mt      = <"> media-type <">
  relation-types = relation-type
                 | <"> relation-type *( 1*SP relation-type ) <">
  relation-type  = reg-rel-type | ext-rel-type
  reg-rel-type   = LOALPHA *( LOALPHA | DIGIT | "." | "-" )
  ext-rel-type   = URI

 See more: rfc5988
*/
bool
find_key_value (const char *start, const char *end, const char *key, char **value)
{
  const char *eq;
  size_t key_len = strlen (key);
  const char *val_beg, *val_end;
  const char *key_beg;

  key_beg = start;

  while (key_beg + key_len + 1 < end)
    {
      /* Skip whitespaces.  */
      while (key_beg + key_len + 1 < end && c_isspace (*key_beg))
        key_beg++;
      if (strncmp (key_beg, key, key_len))
        {
          /* Find next token.  */
          while (key_beg + key_len + 1 < end && *key_beg != ';')
            key_beg++;
          key_beg++;
          continue;
        }
      else
        {
          /* Find equals sign.  */
          eq = key_beg + key_len;
          while (eq < end && c_isspace (*eq))
            eq++;
          if (eq == end)
            return false;
          if (*eq != '=')
            {
              key_beg++;
              continue;
            }

          val_beg = eq + 1;
          while (val_beg < end && c_isspace (*val_beg))
            val_beg++;
          if (val_beg == end)
            return false;
          val_end = val_beg + 1;
          while (val_end < end && *val_end != ';' && !c_isspace (*val_end))
            val_end++;
          *value = xstrndup (val_beg, val_end - val_beg);
          return true;
        }
    }
  *value = NULL;
  return false;
}

/* This is to check if given token exists in HTTP header. Tokens are
   separated by ';'. */
bool
has_key (const char *start, const char *end, const char *key)
{
  const char *pos; /* Here would the token start.  */
  size_t key_len = strlen (key);

  pos = start;
  while (pos + key_len <= end)
    {
      /* Skip whitespaces at beginning.  */
      while (pos + key_len <= end && c_isspace (*pos))
        pos++;

      /* Does the prefix of pos match our key?  */
      if (strncmp (key, pos, key_len))
        {
          /* This was not a match.
             Skip all characters until beginning of next token.  */
          while (pos + key_len <= end && *pos != ';')
            pos++;
          pos++;
          continue;
        }

      /* key is prefix of pos. Is it the exact token or just a prefix?  */
      pos += key_len;
      while (pos < end && c_isspace (*pos))
        pos++;
      if (pos == end || *pos == ';')
        return true;

      /* This was not a match (just a prefix).
         Skip all characters until beginning of next token.  */
      while (pos + key_len <= end && *pos != ';')
        pos++;
      pos++;
    }
  return false;
}

/* Find all key=value pairs delimited with ';' or ','. This is intended for
   Digest header parsing.
   The usage is:

   const char *pos;
   for (pos = header_beg; pos = find_key_values (pos, header_end, &key, &val); pos++)
   {
     ...
   }

 */
const char *
find_key_values (const char *start, const char *end, char **key, char **value)
{
  const char *key_start, *key_end;
  const char *eq;
  const char *val_start, *val_end;

  eq = start;
  while (eq < end && *eq != '=')
    {
      /* Skip tokens without =value part.  */
      if (*eq == ';' || *eq == ',')
        start = eq + 1;
      eq++;
    }

  if (eq >= end)
    return NULL;

  key_start = start;
  while (key_start < eq && c_isspace (*key_start))
    key_start++;

  key_end = eq - 1;
  while (key_end > key_start && c_isspace (*key_end))
    key_end--;
  key_end++;

  val_start = eq + 1;
  while (val_start < end && c_isspace (*val_start))
    val_start++;

  val_end = val_start;

  while (val_end < end && *val_end != ';' &&
         *val_end != ',' && !c_isspace (*val_end))
    val_end++;

  *key = xstrndup (key_start, key_end - key_start);
  *value = xstrndup (val_start, val_end - val_start);

  /* Skip trailing whitespaces.  */
  while (val_end < end && c_isspace (*val_end))
    val_end++;

  return val_end;
}

#ifdef TESTING
const char *
test_find_key_values (void)
{
  static const char *header_data = "key1=val1;key2=val2 ;key3=val3; key4=val4"\
                                   " ; key5=val5;key6 =val6;key7= val7; "\
                                   "key8 = val8 ;    key9    =   val9       "\
                                   "    ,key10= val10,key11,key12=val12";
  static const struct
  {
    const char *key;
    const char *val;
  } test_array[] =
  {
    { "key1", "val1" },
    { "key2", "val2" },
    { "key3", "val3" },
    { "key4", "val4" },
    { "key5", "val5" },
    { "key6", "val6" },
    { "key7", "val7" },
    { "key8", "val8" },
    { "key9", "val9" },
    { "key10", "val10" },
    { "key12", "val12" }
  };
  const char *pos;
  char *key, *value;
  size_t i = 0;

  for (pos = header_data; (pos = find_key_values (pos,
                                                 header_data + strlen (header_data),
                                                 &key, &value)); pos++)
    {
      mu_assert ("test_find_key_values: wrong result",
                 !strcmp (test_array[i].val, value) &&
                 !strcmp (test_array[i].key, key));
      xfree (key);
      xfree (value);
      i++;
    }

  return NULL;
}

const char *
test_find_key_value (void)
{
  static const char *header_data = "key1=val1;key2=val2 ;key3=val3; key4=val4"\
                                   " ; key5=val5;key6 =val6;key7= val7; "\
                                   "key8 = val8 ;    key9    =   val9       ";
  static const struct
  {
    const char *key;
    const char *val;
    bool result;
  } test_array[] =
  {
    { "key1",  "val1", true },
    { "key2",  "val2", true },
    { "key3",  "val3", true },
    { "key4",  "val4", true },
    { "key5",  "val5", true },
    { "key6",  "val6", true },
    { "key7",  "val7", true },
    { "key8",  "val8", true },
    { "key9",  "val9", true },
    { "key10", NULL,   false },
    {  "ey1",  NULL,   false },
    { "dey1",  NULL,   false }
  };
  size_t i;

  for (i=0; i < countof (test_array); ++i)
    {
      bool result;
      char *value;

      result = find_key_value (header_data,
                               header_data + strlen(header_data),
                               test_array[i].key, &value);

      mu_assert ("test_find_key_value: wrong result",
                 result == test_array[i].result &&
                 ((!test_array[i].result && !value) ||
                  !strcmp (value, test_array[i].val)));

      xfree (value);
    }

  return NULL;
}

const char *
test_has_key (void)
{
  static const char *header_data = "key1=val2;token1;xyz; token2;xyz;token3 ;"\
                                   "xyz; token4 ;xyz;   token5  ";
  struct
  {
    const char *token;
    bool result;
  } test_array[] =
  {
    { "key1=val2", true },
    { "token1", true },
    { "token2", true },
    { "token3", true },
    { "token4", true },
    { "token5", true },
    { "token6", false },
    { "oken1", false },
    { "poken1", false },
    { "key1=val2", true }
  };
  size_t i;

  for (i = 0; i < countof (test_array); ++i)
    mu_assert ("test_has_key: wrong result",
               has_key (header_data, header_data + strlen (header_data),
                        test_array[i].token) == test_array[i].result);

  return NULL;
}
#endif

#endif /* HAVE_METALINK */
