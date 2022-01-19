/* Utility functions for writing WARC files.
   Copyright (C) 2011-2012, 2015, 2018-2022 Free Software Foundation,
   Inc.

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
#include "hash.h"
#include "utils.h"
#include "version.h"
#include "dirname.h"
#include "url.h"
#include "luahooks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tmpdir.h>
#include <sha1.h>
#include <base32.h>
#include <unistd.h>
#ifdef HAVE_LIBZ
#include <zlib.h>
#endif
#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#ifdef HAVE_LIBUUID
#include <uuid/uuid.h>
#elif HAVE_UUID_CREATE
#include <uuid.h>
#endif

#include "warc.h"
#include "exits.h"

#ifdef WINDOWS
/* we need this on Windows to have O_TEMPORARY defined */
# include <fcntl.h>
# include <rpc.h>
#endif

#ifndef O_TEMPORARY
#define O_TEMPORARY 0
#endif

#include "warc.h"
#include "exits.h"


/* The log file (a temporary file that contains a copy
   of the wget log). */
static FILE *warc_log_fp;

/* The manifest file (a temporary file that contains the
   warcinfo uuid of every file in this crawl). */
static FILE *warc_manifest_fp;

/* The current WARC file (or NULL, if WARC is disabled). */
static FILE *warc_current_file;

#ifdef HAVE_LIBZ
/* The gzip stream for the current WARC file
   (or NULL, if WARC or gzip is disabled). */
static gzFile warc_current_gzfile;
#endif
#ifdef HAVE_ZSTD
static ZSTD_CCtx *warc_current_zst_context;
static ZSTD_CDict *warc_current_zst_dict;
static FILE *warc_current_zst_dict_file;
static bool warc_current_zst_full_record;
static void *warc_current_zst_dict_buffer;
static size_t warc_current_zst_buffer_in_size;
static void *warc_current_zst_buffer_in;
static size_t warc_current_zst_buffer_out_size;
static void *warc_current_zst_buffer_out;
#endif

#if defined(HAVE_LIBZ) || defined(HAVE_ZSTD)
/* The offset of the current compressed record in the WARC file. */
static off_t warc_current_compressed_file_offset;

/* The uncompressed size (so far) of the current record. */
static off_t warc_current_compressed_file_uncompressed_size;
# endif

/* This is true until a warc_write_* method fails. */
static bool warc_write_ok;

/* The current CDX file (or NULL, if CDX is disabled). */
static FILE *warc_current_cdx_file;

/* The record id of the warcinfo record of the current WARC file.  */
static char warc_current_warcinfo_uuid_str[48];

/* The file name of the current WARC file. */
static char *warc_current_filename;

/* The serial number of the current WARC file.  This number is
   incremented each time a new file is opened and is used in the
   WARC file's filename. */
static int warc_current_file_number;

/* The table of CDX records, if deduplication is enabled. */
static struct hash_table * warc_dedup_table;

static bool warc_start_new_file (bool meta);


struct warc_dedup_record
{
  char *uri;
  char *date;
  char *uuid;
  char *digest[SHA1_DIGEST_SIZE];
};

struct warc_dedup_key
{
  char *uri;
  char digest[SHA1_DIGEST_SIZE];
};

/* Calculates the hash of the warc_dedup_key for the hash table. If URL agnostic
   deduplication is enabled, a SHA1 hash is calculated over the url, after which
   a final SHA1 hash is calculated over the combination of the digest and the
   hash of the URL. If not URL agnostic deduplication is used the digest is
   used as final SHA1 hash.

   The first bytes of the SHA1 hash are used as unsigned long hash for the hash
   table. */
static unsigned long
warc_hash_sha1_digest (const void *key)
{
  const struct warc_dedup_key *dedup_key = key;
  unsigned long v = 0;

  /* If URL agnostic deduplication is enabled, only the payload SHA1 hash is
     used for the hash table index. If this is not enabled, the URI is hashed
     as well and a hash of the concatenated digest and URI hashes is used for
     the hash table index. */
  if (opt.warc_dedup_url_agnostic)
    memcpy (&v, dedup_key->digest, sizeof (unsigned long));
  else
    {
      char digest[SHA1_DIGEST_SIZE*2];
      char compare_digest[SHA1_DIGEST_SIZE];

      memcpy(digest, dedup_key->digest, SHA1_DIGEST_SIZE);
      sha1_buffer(dedup_key->uri, strlen(dedup_key->uri),
                  digest + SHA1_DIGEST_SIZE);
      sha1_buffer(digest, SHA1_DIGEST_SIZE*2, compare_digest);

      memcpy (&v, compare_digest, sizeof (unsigned long));
    }

  return v;
}

/* Checks the exact identity of the data from the hash table. If URL agnostic
   deduplication is enabled, only the digest is compared, else both the URL and
   the digest are compared. */
static int
warc_cmp_sha1_digest (const void *key1, const void *key2)
{
  const struct warc_dedup_key *record1 = key1;
  const struct warc_dedup_key *record2 = key2;

  return memcmp (record1->digest, record2->digest, SHA1_DIGEST_SIZE) == 0 &&
      (strcmp (record1->uri, record2->uri) == 0 || opt.warc_dedup_url_agnostic);
}



/* Writes SIZE bytes from BUFFER to the current WARC file,
   through gzwrite or zstd if compression is enabled.
   Returns the number of uncompressed bytes written.  */
static size_t
warc_write_buffer (const char *buffer, size_t size)
{
#ifdef HAVE_LIBZ
  if (warc_current_gzfile)
    {
      warc_current_compressed_file_uncompressed_size += size;
      return gzwrite (warc_current_gzfile, buffer, size);
    }
#endif
#ifdef HAVE_ZSTD
#ifdef HAVE_LIBZ
  else
#endif
  if (warc_current_zst_context)
    {
      warc_current_compressed_file_uncompressed_size += size;
      ZSTD_inBuffer input = { buffer, size, 0 };
      ZSTD_EndDirective mode = warc_current_zst_full_record ? ZSTD_e_end : ZSTD_e_continue;
      bool finished;
      do
        {
          ZSTD_outBuffer output = { warc_current_zst_buffer_out,
                                   warc_current_zst_buffer_out_size, 0 };
          size_t remaining = ZSTD_compressStream2 (warc_current_zst_context,
                                                   &output, &input, mode);

          if (ZSTD_isError(remaining))
            {
              logprintf (LOG_NOTQUIET,
                         _("Error compressing data.\n"));
              warc_write_ok = false;
              return 0;
            }

          size_t written = fwrite(warc_current_zst_buffer_out, 1, output.pos,
                                  warc_current_file);
          if (written != output.pos)
            {
              logprintf (LOG_NOTQUIET,
                         _("Error writing to WARC ZST file.\n"));
              warc_write_ok = false;
              return 0;
            }
          finished = warc_current_zst_full_record ? (remaining == 0) : (input.pos == input.size);
        } while (! finished);
      if (input.pos != input.size)
        {
          logprintf (LOG_NOTQUIET,
                     _("Error reading all compressed data from buffer.\n"));
          warc_write_ok = false;
          return 0;
        }
      return size;
    }
  else
#endif
    if (fwrite (buffer, 1, size, warc_current_file) != size)
      {
        warc_write_ok = false;
        return 0;
      }
    else
      return size;
}

/* Writes STR to the current WARC file.
   Returns false and set warc_write_ok to false if there
   is an error.  */
static bool
warc_write_string (const char *str)
{
  size_t n;

  if (!warc_write_ok)
    return false;

  n = strlen (str);
  if (n != warc_write_buffer (str, n))
    warc_write_ok = false;

  return warc_write_ok;
}


#define EXTRA_GZIP_HEADER_SIZE 14
#define GZIP_STATIC_HEADER_SIZE  10
#define FLG_FEXTRA          0x04
#define OFF_FLG             3

/* Starts a new WARC record.  Writes the version header.
   If opt.warc_maxsize is set and the current file is becoming
   too large, this will open a new WARC file.

   If compression is enabled, this will start a new
   gzip stream in the current WARC file.

   Returns false and set warc_write_ok to false if there
   is an error.  */
static bool
warc_write_start_record (void)
{
  if (!warc_write_ok)
    return false;

  if (fflush (warc_current_file) != 0)
    {
      warc_write_ok = false;
      return false;
    }

  if (opt.warc_maxsize > 0)
    {
      warc_current_compressed_file_offset = ftello (warc_current_file);
      if (warc_current_compressed_file_offset < 0)
        {
          warc_write_ok = false;
          return false;
        }
      if (warc_current_compressed_file_offset >= opt.warc_maxsize)
        warc_start_new_file (false);
    }

#if defined(HAVE_LIBZ) || defined(HAVE_ZSTD)
  /* Start a GZIP or ZSTD stream, if required. */
  if (opt.warc_compression_enabled)
    {
      warc_current_compressed_file_offset = ftello (warc_current_file);
      if (warc_current_compressed_file_offset < 0)
        {
          warc_write_ok = false;
          return false;
        }
      warc_current_compressed_file_uncompressed_size = 0;
#ifdef HAVE_ZSTD
      if (opt.warc_compression_use_zstd)
        {
          warc_current_zst_full_record = false;
        }
#ifdef HAVE_LIBZ
      else
#endif
#endif
#ifdef HAVE_LIBZ
        {
          int dup_fd;
          /* Record the starting offset of the new record. */

          /* Reserve space for the extra GZIP header field.
             In warc_write_end_record we will fill this space
             with information about the uncompressed and
             compressed size of the record. */
          if (fseek (warc_current_file, EXTRA_GZIP_HEADER_SIZE, SEEK_CUR) < 0)
            {
              logprintf (LOG_NOTQUIET, _("Error setting WARC file position.\n"));
              warc_write_ok = false;
              return false;
            }

          if (fflush (warc_current_file) != 0)
            {
              logprintf (LOG_NOTQUIET, _("Error flushing WARC file to disk.\n"));
              warc_write_ok = false;
              return false;
            }

          /* Start a new GZIP or ZSTD stream. */
          dup_fd = dup (fileno (warc_current_file));
          if (dup_fd < 0)
            {
              logprintf (LOG_NOTQUIET,
                         _("Error duplicating WARC file file descriptor.\n"));
              warc_write_ok = false;
              return false;
            }

          warc_current_gzfile = gzdopen (dup_fd, "wb9");

          if (warc_current_gzfile == NULL)
            {
              logprintf (LOG_NOTQUIET,
                         _("Error opening GZIP stream to WARC file.\n"));
              close (dup_fd);
              warc_write_ok = false;
              return false;
            }
        }
#endif
    }
#endif

  warc_write_string ("WARC/1.1\r\n");
  return warc_write_ok;
}

/* Writes a WARC header to the current WARC record.
   This method may be run after warc_write_start_record and
   before warc_write_block_from_file.  */
static bool
warc_write_header (const char *name, const char *value)
{
  if (value)
    {
      warc_write_string (name);
      warc_write_string (": ");
      warc_write_string (value);
      warc_write_string ("\r\n");
    }
  return warc_write_ok;
}

/* Copies the contents of DATA_IN to the WARC record.
   Adds a Content-Length header to the WARC record.
   Run this method after warc_write_header,
   then run warc_write_end_record. */
static bool
warc_write_block_from_file (FILE *data_in)
{
  /* Add the Content-Length header. */
  off_t content_length_i;
  char content_length[MAX_INT_TO_STRING_LEN(off_t)];
  size_t buffer_size;
#ifdef HAVE_ZSTD
  if (warc_current_zst_context != NULL)
    buffer_size = warc_current_zst_buffer_out_size;
  else
#endif
    buffer_size = BUFSIZ;
  char buffer[buffer_size];
  size_t s;

  if (fseeko (data_in, 0L, SEEK_END) != 0)
    warc_write_ok = false;

  content_length_i = ftello (data_in);
  if (content_length_i < 0)
    warc_write_ok = false;

  number_to_string (content_length, content_length_i);
  warc_write_header ("Content-Length", content_length);

  /* End of the WARC header section. */
  warc_write_string ("\r\n");

  if (fseeko (data_in, 0L, SEEK_SET) != 0)
    warc_write_ok = false;

  /* Copy the data in the file to the WARC record. */
  while (warc_write_ok && (s = fread (buffer, 1, buffer_size, data_in)) > 0)
    {
      if (warc_write_buffer (buffer, s) < s)
        warc_write_ok = false;
    }

  return warc_write_ok;
}

/* Run this method to close the current WARC record.

   If compression is enabled, this method closes the
   current GZIP stream and fills the extra GZIP header
   with the uncompressed and compressed length of the
   record. */
static bool
warc_write_end_record (void)
{
#ifdef HAVE_ZSTD
  if (opt.warc_compression_use_zstd)
    warc_current_zst_full_record = true;
#endif
  if (warc_write_buffer ("\r\n\r\n", 4) != 4)
    {
      warc_write_ok = false;
      return false;
    }

#ifdef HAVE_LIBZ
  /* We start a new gzip stream for each record.  */
  if (warc_write_ok && warc_current_gzfile)
    {
      char extra_header[EXTRA_GZIP_HEADER_SIZE];
      char static_header[GZIP_STATIC_HEADER_SIZE];
      off_t current_offset, uncompressed_size, compressed_size;
      size_t result;

      if (gzclose (warc_current_gzfile) != Z_OK)
        {
          warc_write_ok = false;
          return false;
        }

      if (fflush (warc_current_file) != 0
          || fseeko (warc_current_file, 0, SEEK_END) != 0)
        {
          warc_write_ok = false;
          return false;
        }

      /* The WARC standard suggests that we add 'skip length' data in the
         extra header field of the GZIP stream.

         In warc_write_start_record we reserved space for this extra header.
         This extra space starts at warc_current_compressed_file_offset and fills
         EXTRA_GZIP_HEADER_SIZE bytes.  The static GZIP header starts at
         warc_current_compressed_file_offset + EXTRA_GZIP_HEADER_SIZE.

         We need to do three things:
         1. Move the static GZIP header to warc_current_compressed_file_offset;
         2. Set the FEXTRA flag in the GZIP header;
         3. Write the extra GZIP header after the static header, that is,
            starting at warc_current_compressed_file_offset + GZIP_STATIC_HEADER_SIZE.
      */

      /* Calculate the uncompressed and compressed sizes. */
      current_offset = ftello (warc_current_file);
      if (current_offset < 0)
        {
          warc_write_ok = false;
          return false;
        }

      uncompressed_size = current_offset - warc_current_compressed_file_offset;
      compressed_size = warc_current_compressed_file_uncompressed_size;

      /* Go back to the static GZIP header. */
      result = fseeko (warc_current_file, warc_current_compressed_file_offset
              + EXTRA_GZIP_HEADER_SIZE, SEEK_SET);
      if (result != 0)
        {
          warc_write_ok = false;
          return false;
        }

      /* Read the header. */
      if (fread (static_header, 1, GZIP_STATIC_HEADER_SIZE,
                 warc_current_file) != GZIP_STATIC_HEADER_SIZE)
        {
          warc_write_ok = false;
          return false;
        }

      /* Set the FEXTRA flag in the flags byte of the header. */
      static_header[OFF_FLG] = static_header[OFF_FLG] | FLG_FEXTRA;

      /* Write the header back to the file, but starting at
         warc_current_compressed_file_offset. */
      if (fseeko (warc_current_file, warc_current_compressed_file_offset,
                  SEEK_SET) != 0
          || fwrite (static_header, 1, GZIP_STATIC_HEADER_SIZE,
                     warc_current_file) != GZIP_STATIC_HEADER_SIZE)
        {
          warc_write_ok = false;
          return false;
        }

      /* Prepare the extra GZIP header. */
      /* XLEN, the length of the extra header fields.  */
      extra_header[0]  = ((EXTRA_GZIP_HEADER_SIZE - 2) & 255);
      extra_header[1]  = ((EXTRA_GZIP_HEADER_SIZE - 2) >> 8) & 255;
      /* The extra header field identifier for the WARC skip length. */
      extra_header[2]  = 's';
      extra_header[3]  = 'l';
      /* The size of the field value (8 bytes).  */
      extra_header[4]  = (8 & 255);
      extra_header[5]  = ((8 >> 8) & 255);
      /* The size of the uncompressed record.  */
      extra_header[6]  = (uncompressed_size & 255);
      extra_header[7]  = (uncompressed_size >> 8) & 255;
      extra_header[8]  = (uncompressed_size >> 16) & 255;
      extra_header[9]  = (uncompressed_size >> 24) & 255;
      /* The size of the compressed record.  */
      extra_header[10] = (compressed_size & 255);
      extra_header[11] = (compressed_size >> 8) & 255;
      extra_header[12] = (compressed_size >> 16) & 255;
      extra_header[13] = (compressed_size >> 24) & 255;

      /* Write the extra header after the static header. */
      if (fseeko (warc_current_file, warc_current_compressed_file_offset
                  + GZIP_STATIC_HEADER_SIZE, SEEK_SET) != 0
          || fwrite (extra_header, 1, EXTRA_GZIP_HEADER_SIZE,
                     warc_current_file) != EXTRA_GZIP_HEADER_SIZE
          /* Done, move back to the end of the file. */
          || fflush (warc_current_file) != 0
          || fseeko (warc_current_file, 0, SEEK_END) != 0)
        {
          warc_write_ok = false;
          return false;
        }

      if (ferror (warc_current_file))
        {
          warc_write_ok = false;
          return false;
        }

    }
#endif

  return warc_write_ok;
}


/* Writes the WARC-Date header for the given timestamp to
   the current WARC record.
   If timestamp is NULL, the current time will be used.  */
static char *
warc_write_date_header (const char *timestamp)
{
  char *current_timestamp;

  if (timestamp)
    current_timestamp = xstrdup (timestamp);
  else
    {
      current_timestamp = xmalloc (21);
      warc_timestamp (current_timestamp, 21);
    }

  if (! warc_write_header ("WARC-Date", current_timestamp))
    return NULL;
  return current_timestamp;
}

/* Writes the WARC-IP-Address header for the given IP to
   the current WARC record.  If IP is NULL, no header will
   be written.  */
static bool
warc_write_ip_header (const ip_address *ip)
{
  if (ip != NULL)
    return warc_write_header ("WARC-IP-Address", print_address (ip));
  else
    return warc_write_ok;
}


/* warc_sha1_stream_with_payload is a modified copy of sha1_stream
   from gnulib/sha1.c.  This version calculates two digests in one go.

   Compute SHA1 message digests for bytes read from STREAM.  The
   digest of the complete file will be written into the 16 bytes
   beginning at RES_BLOCK.

   If payload_offset >= 0, a second digest will be calculated of the
   portion of the file starting at payload_offset and continuing to
   the end of the file.  The digest number will be written into the
   16 bytes beginning ad RES_PAYLOAD.  */
static int
warc_sha1_stream_with_payload (FILE *stream, void *res_block, void *res_payload,
                               off_t payload_offset)
{
#define BLOCKSIZE 32768

  struct sha1_ctx ctx_block;
  struct sha1_ctx ctx_payload;
  off_t pos;
  off_t sum;

  char *buffer = xmalloc (BLOCKSIZE + 72);

  /* Initialize the computation context.  */
  sha1_init_ctx (&ctx_block);
  if (payload_offset >= 0)
    sha1_init_ctx (&ctx_payload);

  pos = 0;

  /* Iterate over full file contents.  */
  while (1)
    {
      /* We read the file in blocks of BLOCKSIZE bytes.  One call of the
         computation function processes the whole buffer so that with the
         next round of the loop another block can be read.  */
      off_t n;
      sum = 0;

      /* Read block.  Take care for partial reads.  */
      while (1)
        {
          n = fread (buffer + sum, 1, BLOCKSIZE - sum, stream);

          sum += n;
          pos += n;

          if (sum == BLOCKSIZE)
            break;

          if (n == 0)
            {
              /* Check for the error flag IF N == 0, so that we don't
                 exit the loop after a partial read due to e.g., EAGAIN
                 or EWOULDBLOCK.  */
              if (ferror (stream))
                {
                  xfree (buffer);
                  return 1;
                }
              goto process_partial_block;
            }

          /* We've read at least one byte, so ignore errors.  But always
             check for EOF, since feof may be true even though N > 0.
             Otherwise, we could end up calling fread after EOF.  */
          if (feof (stream))
            goto process_partial_block;
        }

      /* Process buffer with BLOCKSIZE bytes.  Note that
                        BLOCKSIZE % 64 == 0
       */
      sha1_process_block (buffer, BLOCKSIZE, &ctx_block);
      if (payload_offset >= 0 && payload_offset < pos)
        {
          /* At least part of the buffer contains data from payload. */
          off_t start_of_payload = payload_offset - (pos - BLOCKSIZE);
          if (start_of_payload <= 0)
            /* All bytes in the buffer belong to the payload. */
            start_of_payload = 0;

          /* Process the payload part of the buffer.
             Note: we can't use  sha1_process_block  here even if we
             process the complete buffer.  Because the payload doesn't
             have to start with a full block, there may still be some
             bytes left from the previous buffer.  Therefore, we need
             to continue with  sha1_process_bytes.  */
          sha1_process_bytes (buffer + start_of_payload,
                              BLOCKSIZE - start_of_payload, &ctx_payload);
        }
    }

 process_partial_block:;

  /* Process any remaining bytes.  */
  if (sum > 0)
    {
      sha1_process_bytes (buffer, sum, &ctx_block);
      if (payload_offset >= 0 && payload_offset < pos)
        {
          /* At least part of the buffer contains data from payload. */
          off_t start_of_payload = payload_offset - (pos - sum);
          if (start_of_payload <= 0)
            /* All bytes in the buffer belong to the payload. */
            start_of_payload = 0;

          /* Process the payload part of the buffer. */
          sha1_process_bytes (buffer + start_of_payload,
                              sum - start_of_payload, &ctx_payload);
        }
    }

  /* Construct result in desired memory.  */
  sha1_finish_ctx (&ctx_block,   res_block);
  if (payload_offset >= 0)
    sha1_finish_ctx (&ctx_payload, res_payload);
  xfree (buffer);
  return 0;

#undef BLOCKSIZE
}

/* Converts the SHA1 digest to a base32-encoded string.
   "sha1:DIGEST\0"  (Allocates a new string for the response.)  */
static char *
warc_base32_sha1_digest (const char *sha1_digest, char *sha1_base32, size_t sha1_base32_size)
{
  if (sha1_base32_size >= BASE32_LENGTH(SHA1_DIGEST_SIZE) + 5 + 1)
    {
      memcpy (sha1_base32, "sha1:", 5);
      base32_encode (sha1_digest, SHA1_DIGEST_SIZE, sha1_base32 + 5,
                     sha1_base32_size - 5);
    }
  else
    *sha1_base32 = 0;

  return sha1_base32;
}


/* Sets the digest headers of the record.
   This method will calculate the block digest and, if payload_offset >= 0,
   will also calculate the payload digest of the payload starting at the
   provided offset.  */
static void
warc_write_digest_headers (FILE *file, long payload_offset)
{
  if (opt.warc_digests_enabled)
    {
      /* Calculate the block and payload digests. */
      char sha1_res_block[SHA1_DIGEST_SIZE];
      char sha1_res_payload[SHA1_DIGEST_SIZE];

      rewind (file);
      if (warc_sha1_stream_with_payload (file, sha1_res_block,
          sha1_res_payload, payload_offset) == 0)
        {
          char digest[BASE32_LENGTH(SHA1_DIGEST_SIZE) + 1 + 5];

          warc_write_header ("WARC-Block-Digest",
              warc_base32_sha1_digest (sha1_res_block, digest, sizeof(digest)));

          if (payload_offset >= 0)
              warc_write_header ("WARC-Payload-Digest",
                  warc_base32_sha1_digest (sha1_res_payload, digest, sizeof(digest)));
        }
    }
}


/* Fills timestamp with the current time and date.
   The UTC time is formatted following ISO 8601, as required
   for use in the WARC-Date header.
   The timestamp will be 21 characters long. */
char *
warc_timestamp (char *timestamp, size_t timestamp_size)
{
  time_t rawtime = time (NULL);
  struct tm * timeinfo = gmtime (&rawtime);

  if (strftime (timestamp, timestamp_size, "%Y-%m-%dT%H:%M:%SZ", timeinfo) == 0
      && timestamp_size > 0)
    *timestamp = 0;

  return timestamp;
}

/* Fills urn_str with a UUID in the format required
   for the WARC-Record-Id header.
   The string will be 47 characters long. */
#if HAVE_LIBUUID
void
warc_uuid_str (char *urn_str, size_t urn_size)
{
  char uuid_str[37];
  uuid_t record_id;

  uuid_generate (record_id);
  uuid_unparse (record_id, uuid_str);

  if (snprintf (urn_str, urn_size, "<urn:uuid:%s>", uuid_str) < 0)
    warc_write_ok = false;
}
#elif HAVE_UUID_CREATE
void
warc_uuid_str (char *urn_str, size_t urn_size)
{
  char *uuid_str;
  uuid_t record_id;

  uuid_create (&record_id, NULL);
  uuid_to_string (&record_id, &uuid_str, NULL);

  if (snprintf (urn_str, urn_size, "<urn:uuid:%s>", uuid_str) < 0)
    warc_write_ok = false;
  xfree (uuid_str);
}
#else
# ifdef WINDOWS

typedef RPC_STATUS (RPC_ENTRY * UuidCreate_proc) (UUID *);
typedef RPC_STATUS (RPC_ENTRY * UuidToString_proc) (UUID *, unsigned char **);
typedef RPC_STATUS (RPC_ENTRY * RpcStringFree_proc) (unsigned char **);

static int
windows_uuid_str (char *urn_str, size_t urn_size)
{
  static UuidCreate_proc pfn_UuidCreate = NULL;
  static UuidToString_proc pfn_UuidToString = NULL;
  static RpcStringFree_proc pfn_RpcStringFree = NULL;
  static int rpc_uuid_avail = -1;

  /* Rpcrt4.dll is not available on older versions of Windows, so we
     need to test its availability at run time.  */
  if (rpc_uuid_avail == -1)
    {
      HMODULE hm_rpcrt4 = LoadLibrary ("Rpcrt4.dll");

      if (hm_rpcrt4)
      {
        pfn_UuidCreate =
          (UuidCreate_proc) GetProcAddress (hm_rpcrt4, "UuidCreate");
        pfn_UuidToString =
          (UuidToString_proc) GetProcAddress (hm_rpcrt4, "UuidToStringA");
        pfn_RpcStringFree =
          (RpcStringFree_proc) GetProcAddress (hm_rpcrt4, "RpcStringFreeA");
        if (pfn_UuidCreate && pfn_UuidToString && pfn_RpcStringFree)
          rpc_uuid_avail = 1;
        else
          rpc_uuid_avail = 0;
      }
      else
      rpc_uuid_avail = 0;
    }

  if (rpc_uuid_avail)
    {
      BYTE *uuid_str;
      UUID  uuid;

      if (pfn_UuidCreate (&uuid) == RPC_S_OK)
        {
          if (pfn_UuidToString (&uuid, &uuid_str) == RPC_S_OK)
            {
              if (snprintf (urn_str, urn_size, "<urn:uuid:%s>", uuid_str) < 0)
                warc_write_ok = false;
              pfn_RpcStringFree (&uuid_str);
              return 1;
            }
        }
    }
  return 0;
}
#endif
/* Fills urn_str with a UUID based on random numbers in the format
   required for the WARC-Record-Id header.
   (See RFC 4122, UUID version 4.)

   Note: this is a fallback method, it is much better to use the
   methods provided by libuuid.

   The string will be 47 characters long. */
void
warc_uuid_str (char *urn_str, size_t urn_size)
{
  /* RFC 4122, a version 4 UUID with only random numbers */

  unsigned char uuid_data[16];
  int i;

#ifdef WINDOWS
  /* If the native method fails (expected on older Windows versions),
     use the fallback below.  */
  if (windows_uuid_str (urn_str, urn_size))
    return;
#endif

  for (i=0; i<16; i++)
    uuid_data[i] = random_number (255);

  /* Set the four most significant bits (bits 12 through 15) of the
     time_hi_and_version field to the 4-bit version number */
  uuid_data[6] = (uuid_data[6] & 0x0F) | 0x40;

  /* Set the two most significant bits (bits 6 and 7) of the
     clock_seq_hi_and_reserved to zero and one, respectively. */
  uuid_data[8] = (uuid_data[8] & 0xBF) | 0x80;

  if (snprintf (urn_str, urn_size,
      "<urn:uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x>",
      uuid_data[0], uuid_data[1], uuid_data[2], uuid_data[3], uuid_data[4],
      uuid_data[5], uuid_data[6], uuid_data[7], uuid_data[8], uuid_data[9],
      uuid_data[10], uuid_data[11], uuid_data[12], uuid_data[13], uuid_data[14],
      uuid_data[15]) < 0)
    warc_write_ok = false;
}
#endif

/* Write a warcinfo record to the current file.
   Updates warc_current_warcinfo_uuid_str. */
static bool
warc_write_warcinfo_record (const char *filename)
{
  FILE *warc_tmp;
  char timestamp[22];
  char *filename_basename;

  /* Write warc-info record as the first record of the file. */
  /* We add the record id of this info record to the other records in the
     file. */
  warc_uuid_str (warc_current_warcinfo_uuid_str, sizeof (warc_current_warcinfo_uuid_str));

  warc_timestamp (timestamp, sizeof(timestamp));

  filename_basename = base_name (filename);

  warc_write_start_record ();
  warc_write_header ("WARC-Type", "warcinfo");
  warc_write_header ("Content-Type", "application/warc-fields");
  warc_write_header ("WARC-Date", timestamp);
  warc_write_header ("WARC-Record-ID", warc_current_warcinfo_uuid_str);
  warc_write_header ("WARC-Filename", filename_basename);

  xfree (filename_basename);

  /* Create content.  */
  warc_tmp = warc_tempfile ();
  if (warc_tmp == NULL)
    {
      return false;
    }

  if (fprintf (warc_tmp, "software: Wget/%s (%s)\r\n", version_string, OS_TYPE) < 0
      || fprintf (warc_tmp, "format: WARC File Format 1.1\r\n") < 0
      || fprintf (warc_tmp,
"conformsTo: http://bibnum.bnf.fr/WARC/WARC_ISO_28500_version1-1_latestdraft.pdf\r\n") < 0
      || fprintf (warc_tmp, "robots: %s\r\n", (opt.use_robots ? "classic" : "off"))  < 0
      || fprintf (warc_tmp, "wget-arguments: %s\r\n", program_argstring)  < 0)
    {
      warc_write_ok = false;
      return false;
    }

  /* Add the user headers, if any. */
  if (opt.warc_user_headers)
    {
      int i;
      for (i = 0; opt.warc_user_headers[i]; i++)
        if (fprintf (warc_tmp, "%s\r\n", opt.warc_user_headers[i]) < 0)
          {
            warc_write_ok = false;
            return false;
          }
    }

  if (fprintf (warc_tmp, "\r\n") < 0
      || fflush (warc_tmp) != 0)
    {
      warc_write_ok = false;
      return false;
    }

  warc_write_digest_headers (warc_tmp, -1);
  warc_write_block_from_file (warc_tmp);
  warc_write_end_record ();

  if (ferror (warc_tmp) || fclose (warc_tmp) != 0)
    warc_write_ok = false;

  if (! warc_write_ok)
    logprintf (LOG_NOTQUIET, _("Error writing warcinfo record to WARC file.\n"));

  return warc_write_ok;
}

#ifdef HAVE_ZSTD
/* Writes an integer to the WARC file, this is for the ZSTD header.
   */
static bool
warc_write_integer (int num)
{
  unsigned char s[4];

  for (int i = 0; i < 4; i++)
    {
      s[i] = (unsigned char)(num & 0xff);
      num >>= 8;
    }

  if (fwrite(s, 1, 4, warc_current_file) != 4)
    {
      logprintf (LOG_NOTQUIET, _("Error writing number of ZST skippable frame.\n"));
      warc_write_ok = false;
      return false;
    }
}


/* Writes the ZSTD dictionary to the WARC file.

   The dictionary is stored in a skippable frame. This frame has MAGIC
   0x184d2a5d, followed a by a header of length 4 bytes containing the size of
   the dictionary data. The dictionary data follows after that. The next frame
   if a ZST frame with the WARC data.

   Returns true on success, false otherwise.
   */
static bool
warc_write_zstd_dictionary (const char *buffer, size_t size)
{
  if (opt.warc_zstd_dict)
    {
      char size_string[4];
      int final_size;

      if (fwrite ("\x5d\x2a\x4d\x18", 1, 4, warc_current_file) != 4)
        {
          logprintf (LOG_NOTQUIET, _("Error writing magic of skippable ZST frame.\n"));
          warc_write_ok = false;
          return false;
        }

      if (opt.warc_zstd_dict_no_compression)
        {
          final_size = (int) size;
          warc_write_integer (final_size);
          if (fwrite (buffer, 1, size, warc_current_file) != size)
            {
              logprintf (LOG_NOTQUIET, _("Error writing ZST dictionary frame.\n"));
              warc_write_ok = false;
              return false;
            }
        }
      else
        {
          size_t compress_buffer_size = ZSTD_compressBound (size);
          char *compress_buffer = xmalloc (compress_buffer_size);
          size_t compress_size = ZSTD_compress (compress_buffer,
            compress_buffer_size, buffer, size, 9);
          if (ZSTD_isError (compress_size))
            {
              logprintf (LOG_NOTQUIET, _("Error compression ZST dictionary.\n"));
              warc_write_ok = false;
              return false;
            }
          final_size = (int) compress_size;
          warc_write_integer (final_size);

          if (fwrite (compress_buffer, 1, compress_size, warc_current_file) != compress_size)
            {
              logprintf (LOG_NOTQUIET, _("Error writing ZST dictionary frame.\n"));
              warc_write_ok = false;
              return false;
            }

          xfree (compress_buffer);
        }
    }
  return true;
}
#endif

/* Opens a new WARC file.
   If META is true, generates a filename ending with 'meta.warc.gz'.

   This method will:
   1. close the current WARC file (if there is one);
   2. increment warc_current_file_number;
   3. open a new WARC file;
   4. write the initial warcinfo record.

   Returns true on success, false otherwise.
   */
static bool
warc_start_new_file (bool meta)
{
#ifdef __VMS
# define WARC_GZ "warc-gz"
# define WARC_ZST "warc-zst"
#else /* def __VMS */
# define WARC_GZ "warc.gz"
# define WARC_ZST "warc.zst"
#endif /* def __VMS [else] */

  char *extension;

#if defined(HAVE_LIBZ) || defined(HAVE_ZSTD)
  if (opt.warc_compression_enabled)
    {
#ifdef HAVE_ZSTD
      if (opt.warc_compression_use_zstd)
        extension = WARC_ZST;
#ifdef HAVE_LIBZ
      else
#endif
#endif
#ifdef HAVE_LIBZ
        extension = WARC_GZ;
#endif
    }
  else
#endif
    extension = "warc";

  int base_filename_length;
  char *new_filename;
  int print_returned;

  if (opt.warc_filename == NULL)
    return false;

  if (warc_current_file != NULL && fclose (warc_current_file) != 0)
    return false;

  *warc_current_warcinfo_uuid_str = 0;
  xfree (warc_current_filename);

  warc_current_file_number++;

  /* init the hash table */
  warc_dedup_table = hash_table_new (1000, warc_hash_sha1_digest,
                                     warc_cmp_sha1_digest);

  base_filename_length = strlen (opt.warc_filename);
  /* filename format:  base + "-" + 5 digit serial number + ".warc.zst" */
  new_filename = xmalloc (base_filename_length + 1 + 5 + 9 + 1);

  warc_current_filename = new_filename;

  /* If max size is enabled, we add a serial number to the file names. */
  if (meta)
    print_returned = sprintf (new_filename, "%s-meta.%s", opt.warc_filename, extension);
  else if (opt.warc_maxsize > 0)
    {
      print_returned = sprintf (new_filename, "%s-%05d.%s", opt.warc_filename,
               warc_current_file_number, extension);
    }
  else
    print_returned = sprintf (new_filename, "%s.%s", opt.warc_filename, extension);

  if (print_returned < 0)
    return false;

  logprintf (LOG_VERBOSE, _("Opening WARC file %s.\n\n"), quote (new_filename));

  /* Open the WARC file. */
  warc_current_file = fopen (new_filename, "wb+");
  if (warc_current_file == NULL)
    {
      logprintf (LOG_NOTQUIET, _("Error opening WARC file %s.\n"),
                 quote (new_filename));
      warc_write_ok = false;
      return false;
    }

#ifdef HAVE_ZSTD
  if (opt.warc_compression_use_zstd)
    {
      /* Prepare ZSTD buffer. */
      warc_current_zst_buffer_in_size = ZSTD_CStreamInSize();
      warc_current_zst_buffer_in = xmalloc(warc_current_zst_buffer_in_size);
      warc_current_zst_buffer_out_size = ZSTD_CStreamOutSize();
      warc_current_zst_buffer_out = xmalloc(warc_current_zst_buffer_out_size);

      /* Create reusable ZSTD context. */
      warc_current_zst_context = ZSTD_createCCtx();
      if (warc_current_zst_context == NULL)
        {
          logprintf (LOG_NOTQUIET,
                     _("Error creating ZSTD context.\n"));
          warc_write_ok = false;
          return false;
        }

      /* Add a checksum to ZSTD frames. */
      if (ZSTD_isError (
          ZSTD_CCtx_setParameter (warc_current_zst_context, ZSTD_c_checksumFlag, 1)))
        {
          logprintf(LOG_NOTQUIET,
                    _("Error setting compression parameters.\n"));
          warc_write_ok = false;
          return false;
        }

      if (opt.warc_zstd_dict != NULL)
        {
          warc_current_zst_dict_file = fopen(opt.warc_zstd_dict, "rb");

          if (warc_current_zst_dict_file == NULL
              || fseek(warc_current_zst_dict_file, 0L, SEEK_END) != 0)
            {
              warc_write_ok = false;
              return false;
            }

          /* Read ZSTD dictionary. */
          size_t dict_size = ftell(warc_current_zst_dict_file);
          if (dict_size < 0
              || fseek(warc_current_zst_dict_file, 0L, SEEK_SET) != 0)
            {
              warc_write_ok = false;
              return false;
            }

          warc_current_zst_dict_buffer = xmalloc(dict_size);

          if (fread(warc_current_zst_dict_buffer, 1, dict_size,
                    warc_current_zst_dict_file) != dict_size)
            {
              logprintf (LOG_NOTQUIET, _("Error reading ZSTD dictionary.\n"));
              warc_write_ok = false;
              return false;
            }

          /* Load the ZSTD dictionary. */
          warc_current_zst_dict = ZSTD_createCDict(warc_current_zst_dict_buffer,
                                                   dict_size, 9);
          if (warc_current_zst_dict == NULL)
            {
              logprintf (LOG_NOTQUIET,
                         _("Error loading ZSTD dictionary.\n"));
              warc_write_ok = false;
              return false;
            }

          if (! opt.warc_zstd_dict_no_include &&
              ! warc_write_zstd_dictionary (warc_current_zst_dict_buffer, dict_size))
            {
              warc_write_ok = false;
              return false;
            }

          /* Reference the ZSTD dictionary with the context. */
          if (ZSTD_isError (ZSTD_CCtx_refCDict (warc_current_zst_context,
                                                warc_current_zst_dict)))
            {
              logprintf (LOG_NOTQUIET,
                         _("Error referencing ZSTD dict to content.\n"));
              warc_write_ok = false;
              return false;
            }

          if (fclose(warc_current_zst_dict_file) != 0)
            {
              warc_write_ok = false;
              return false;
            }
          xfree(warc_current_zst_dict_buffer);
        }
    }
#endif

  if (! warc_write_warcinfo_record (new_filename))
    {
      warc_write_ok = false;
      return false;
    }

  /* Add warcinfo uuid to manifest. */
  if (warc_manifest_fp
      && fprintf (warc_manifest_fp, "%s\n", warc_current_warcinfo_uuid_str) < 0)
    warc_write_ok = false;

  return warc_write_ok;
}

/* Opens the CDX file for output. */
static bool
warc_start_cdx_file (void)
{
  char *cdx_filename = aprintf("%s.cdx", opt.warc_filename);
  warc_current_cdx_file = fopen (cdx_filename, "a+");
  free(cdx_filename);

  if (warc_current_cdx_file == NULL)
    return false;

  /* Print the CDX header.
   *
   * a - original url
   * b - date
   * m - mime type
   * s - response code
   * k - new style checksum
   * r - redirect
   * M - meta tags
   * V - compressed arc file offset
   * g - file name
   * u - record-id
   */
  if (fprintf (warc_current_cdx_file, " CDX a b a m s k r M V g u\n") < 0
      || fflush (warc_current_cdx_file) != 0)
    return false;

  return true;
}

/* Store the WARC record in the warc_dedup_table using a warc_dedup_key and a
   warc_dedup_record for the data. Copies all variables to the hash table. */
static void
store_warc_record (const char *uri, const char *date, const char *uuid,
                   const char *digest)
{
  struct warc_dedup_record *rec = xmalloc (sizeof (struct warc_dedup_record));
  struct warc_dedup_key *key = xmalloc (sizeof (struct warc_dedup_key));

  rec->uri = xstrdup (uri);
  rec->date = xstrdup (date);
  rec->uuid = xstrdup (uuid);
  key->uri = xstrdup (uri);
  memcpy (rec->digest, digest, SHA1_DIGEST_SIZE);
  memcpy (key->digest, digest, SHA1_DIGEST_SIZE);

  hash_table_put (warc_dedup_table, key, rec);
}

#define CDX_FIELDSEP " \t\r\n"

/* Parse the CDX header and find the field numbers of the original url,
   checksum and record ID fields. */
static bool
warc_parse_cdx_header (char *lineptr, int *field_num_original_url,
                       int *field_num_checksum, int *field_num_record_id)
{
  char *token;
  char *save_ptr;

  *field_num_original_url = -1;
  *field_num_checksum = -1;
  *field_num_record_id = -1;

  token = strtok_r (lineptr, CDX_FIELDSEP, &save_ptr);

  if (token != NULL && strcmp (token, "CDX") == 0)
    {
      int field_num = 0;
      while (token != NULL)
        {
          token = strtok_r (NULL, CDX_FIELDSEP, &save_ptr);
          if (token != NULL)
            {
              switch (token[0])
                {
                case 'a':
                  *field_num_original_url = field_num;
                  break;
                case 'k':
                  *field_num_checksum = field_num;
                  break;
                case 'u':
                  *field_num_record_id = field_num;
                  break;
                }
            }
          field_num++;
        }
    }

  return *field_num_original_url != -1
         && *field_num_checksum != -1
         && *field_num_record_id != -1;
}

/* Parse the CDX record and add it to the warc_dedup_table hash table. */
static void
warc_process_cdx_line (char *lineptr, int field_num_original_url,
                       int field_num_checksum, int field_num_record_id)
{
  char *original_url = NULL;
  char *checksum = NULL;
  char *record_id = NULL;
  char *token;
  char *save_ptr;
  int field_num = 0;

  /* Read this line to get the fields we need. */
  token = strtok_r (lineptr, CDX_FIELDSEP, &save_ptr);
  while (token != NULL)
    {
      char **val;
      if (field_num == field_num_original_url)
        val = &original_url;
      else if (field_num == field_num_checksum)
        val = &checksum;
      else if (field_num == field_num_record_id)
        val = &record_id;
      else
        val = NULL;

      if (val != NULL)
        *val = xstrdup (token);

      token = strtok_r (NULL, CDX_FIELDSEP, &save_ptr);
      field_num++;
    }

  if (original_url != NULL && checksum != NULL && record_id != NULL)
    {
      /* For some extra efficiency, we decode the base32 encoded
         checksum value.  This should produce exactly SHA1_DIGEST_SIZE
         bytes.  */
      size_t checksum_l;
      char * checksum_v;
      char *digest;
      base32_decode_alloc (checksum, strlen (checksum), &checksum_v,
                           &checksum_l);
      xfree (checksum);

      if (checksum_v != NULL && checksum_l == SHA1_DIGEST_SIZE)
        {
          /* This is a valid line with a valid checksum. */
          memcpy (digest, checksum_v, SHA1_DIGEST_SIZE);
          store_warc_record(original_url, NULL, record_id, digest);
          xfree (checksum_v);
        }
      else
        {
          xfree (original_url);
          xfree (checksum_v);
          xfree (record_id);
        }
    }
  else
    {
      xfree(checksum);
      xfree(original_url);
      xfree(record_id);
    }
}

/* Loads the CDX file from opt.warc_cdx_dedup_filename and fills
   the warc_dedup_table. */
static bool
warc_load_cdx_dedup_file (void)
{
  FILE *f;
  char *lineptr = NULL;
  size_t n = 0;
  ssize_t line_length;
  int field_num_original_url = -1;
  int field_num_checksum = -1;
  int field_num_record_id = -1;

  f = fopen (opt.warc_cdx_dedup_filename, "r");
  if (f == NULL)
    return false;

  /* The first line should contain the CDX header.
     Format:  " CDX x x x x x"
     where x are field type indicators.  For our purposes, we only
     need 'a' (the original url), 'k' (the SHA1 checksum) and
     'u' (the WARC record id). */
  line_length = getline (&lineptr, &n, f);
  if (line_length != -1)
    warc_parse_cdx_header (lineptr, &field_num_original_url,
                           &field_num_checksum, &field_num_record_id);

  /* If the file contains all three fields, read the complete file. */
  if (field_num_original_url == -1
      || field_num_checksum == -1
      || field_num_record_id == -1)
    {
      if (field_num_original_url == -1)
        logprintf (LOG_NOTQUIET,
_("CDX file does not list original urls. (Missing column 'a'.)\n"));
      if (field_num_checksum == -1)
        logprintf (LOG_NOTQUIET,
_("CDX file does not list checksums. (Missing column 'k'.)\n"));
      if (field_num_record_id == -1)
        logprintf (LOG_NOTQUIET,
_("CDX file does not list record ids. (Missing column 'u'.)\n"));
    }
  else
    {
      int nrecords;

      /* Load CDX data into the table. */

      do
        {
          line_length = getline (&lineptr, &n, f);
          if (line_length != -1)
            {
              warc_process_cdx_line (lineptr, field_num_original_url,
                            field_num_checksum, field_num_record_id);
            }

        }
      while (line_length != -1);

      /* Print results. */
      nrecords = hash_table_count (warc_dedup_table);
      logprintf (LOG_VERBOSE, ngettext ("Loaded %d record from CDX.\n\n",
                                        "Loaded %d records from CDX.\n\n",
                                         nrecords),
                              nrecords);
    }

  xfree (lineptr);
  if (fclose (f) != 0)
    {
      return false;
    }

  return true;
}
#undef CDX_FIELDSEP

/* Returns the warc_dedup_record for the already processed WARC record for
   a given payload digest if URL agnostic deduplication is enabled, and else
   for both the URL and payload digest.

   Returns NULL if the URL is not of if the URL and payload digest or only
   payload digest to not match the found record. */
static struct warc_dedup_record *
warc_find_duplicate_cdx_record (const char *url, const char *sha1_digest_payload)
{
  struct warc_dedup_record *rec_existing;
  struct warc_dedup_key *key;

  if (warc_dedup_table == NULL)
    return NULL;

  key = xmalloc (sizeof (struct warc_dedup_key));
  key->uri = xstrdup (url);
  memcpy (key->digest, sha1_digest_payload, SHA1_DIGEST_SIZE);

  rec_existing = hash_table_get (warc_dedup_table, key);

  xfree (key->uri);
  xfree (key);

  if (rec_existing && memcmp (rec_existing->digest, sha1_digest_payload, SHA1_DIGEST_SIZE) == 0
      && (opt.warc_dedup_url_agnostic || strcmp (rec_existing->uri, url) == 0))
    return rec_existing;
  else
    return NULL;
}

/* Initializes the WARC writer (if opt.warc_filename is set).
   This should be called before any WARC record is written. */
void
warc_init (void)
{
  warc_write_ok = true;

  if (opt.warc_filename != NULL)
    {
      if (opt.warc_cdx_dedup_filename != NULL)
        {
          if (! warc_load_cdx_dedup_file ())
            {
              logprintf (LOG_NOTQUIET,
                         _("Could not read CDX file %s for deduplication.\n"),
                         quote (opt.warc_cdx_dedup_filename));
              exit (WGET_EXIT_GENERIC_ERROR);
            }
        }

      warc_manifest_fp = warc_tempfile ();
      if (warc_manifest_fp == NULL)
        {
          logprintf (LOG_NOTQUIET,
                     _("Could not open temporary WARC manifest file.\n"));
          exit (WGET_EXIT_GENERIC_ERROR);
        }

      if (opt.warc_keep_log)
        {
          warc_log_fp = warc_tempfile ();
          if (warc_log_fp == NULL)
            {
              logprintf (LOG_NOTQUIET,
                         _("Could not open temporary WARC log file.\n"));
              exit (WGET_EXIT_GENERIC_ERROR);
            }
          log_set_warc_log_fp (warc_log_fp);
        }

      warc_current_file_number = -1;
      if (! warc_start_new_file (false))
        {
          logprintf (LOG_NOTQUIET, _("Could not open WARC file.\n"));
          exit (WGET_EXIT_GENERIC_ERROR);
        }

      if (opt.warc_cdx_enabled)
        {
          if (! warc_start_cdx_file ())
            {
              logprintf (LOG_NOTQUIET,
                         _("Could not open CDX file for output.\n"));
              exit (WGET_EXIT_GENERIC_ERROR);
            }
        }
    }
}

/* Writes metadata (manifest, configuration, log file) to the WARC file. */
static void
warc_write_metadata (void)
{
  char manifest_uuid[48];
  FILE *warc_tmp_fp;

  /* If there are multiple WARC files, the metadata should be written to a separate file. */
  if (opt.warc_maxsize > 0)
    warc_start_new_file (true);

  warc_uuid_str (manifest_uuid, sizeof (manifest_uuid));

  if (fflush (warc_manifest_fp) != 0)
    {
      warc_write_ok = false;
      exit (WGET_EXIT_GENERIC_ERROR);
    }
  warc_write_metadata_record (manifest_uuid,
                              "metadata://gnu.org/software/wget/warc/MANIFEST.txt",
                              NULL, NULL, NULL, "text/plain",
                              warc_manifest_fp, -1);
  /* warc_write_resource_record has closed warc_manifest_fp. */

  warc_tmp_fp = warc_tempfile ();
  if (warc_tmp_fp == NULL || fflush (warc_tmp_fp) != 0)
    {
      warc_write_ok = false;
      logprintf (LOG_NOTQUIET, _("Could not open temporary WARC file.\n"));
      exit (WGET_EXIT_GENERIC_ERROR);
    }

  if (fprintf (warc_tmp_fp, "%s\n", program_argstring) < 0)
    {
      warc_write_ok = false;
      exit (WGET_EXIT_GENERIC_ERROR);
    }

  warc_write_resource_record (NULL,
                   "metadata://gnu.org/software/wget/warc/wget_arguments.txt",
                              NULL, manifest_uuid, NULL, "text/plain",
                              warc_tmp_fp, -1);
  /* warc_write_resource_record has closed warc_tmp_fp. */

  if (warc_log_fp != NULL)
    {
      warc_write_resource_record (NULL,
                              "metadata://gnu.org/software/wget/warc/wget.log",
                                  NULL, manifest_uuid, NULL, "text/plain",
                                  warc_log_fp, -1);
      /* warc_write_resource_record has closed warc_log_fp. */

      warc_log_fp = NULL;
      log_set_warc_log_fp (NULL);
    }
}

/* Finishes the WARC writing.
   This should be called at the end of the program. */
void
warc_close (void)
{
  int result = 0;

  if (warc_current_file != NULL)
    {
      warc_write_metadata ();
      *warc_current_warcinfo_uuid_str = 0;
      result = fclose (warc_current_file);
      warc_current_file = NULL;
    }

  if (warc_current_cdx_file != NULL && result == 0)
    {
      result = fclose (warc_current_cdx_file);
      warc_current_cdx_file = NULL;
    }

  if (warc_log_fp != NULL && result == 0)
    {
      result = fclose (warc_log_fp);
      log_set_warc_log_fp (NULL);
    }

  if (result != 0)
    warc_write_ok = false;

#ifdef HAVE_ZSTD
  if (opt.warc_compression_use_zstd)
    {
      ZSTD_freeCCtx (warc_current_zst_context);
      xfree (warc_current_zst_buffer_in);
      xfree (warc_current_zst_buffer_out);
      if (opt.warc_zstd_dict != NULL)
        ZSTD_freeCDict (warc_current_zst_dict);
    }
#endif
}

/* Creates a temporary file for writing WARC output.
   The temporary file will be created in opt.warc_tempdir.
   Returns the pointer to the temporary file, or NULL. */
FILE *
warc_tempfile (void)
{
  char filename[100];
  int fd;

  if (path_search (filename, 100, opt.warc_tempdir, "wget", true) == -1)
    return NULL;

#ifdef __VMS
  /* 2013-07-12 SMS.
   * mkostemp()+unlink()+fdopen() scheme causes trouble on VMS, so use
   * mktemp() to uniquify the (VMS-style) name, and then use a normal
   * fopen() with a "create temp file marked for delete" option.
   */
  {
    char *tfn;

    tfn = mktemp (filename);            /* Get unique name from template. */
    if (tfn == NULL)
      return NULL;
    return fopen (tfn, "w+", "fop=tmd");    /* Create auto-delete temp file. */
  }
#else /* def __VMS */
  fd = mkostemp (filename, O_TEMPORARY);
  if (fd < 0)
    return NULL;

#if !O_TEMPORARY
  if (unlink (filename) < 0)
    {
      close(fd);
      return NULL;
    }
#endif

  return fdopen (fd, "wb+");
#endif /* def __VMS [else] */
}


/* Writes a request record to the WARC file.
   url  is the target uri of the request,
   timestamp_str  is the timestamp of the request (generated with warc_timestamp),
   record_uuid  is the uuid of the request (generated with warc_uuid_str),
   body  is a pointer to a file containing the request headers and body.
   ip  is the ip address of the server (or NULL),
   Calling this function will close body.
   Returns true on success, false on error. */
bool
warc_write_request_record (const char *url, const char *timestamp_str,
                           const char *record_uuid, const ip_address *ip,
                           FILE *body, off_t payload_offset)
{
  warc_write_start_record ();
  warc_write_header ("WARC-Type", "request");
  warc_write_header ("WARC-Target-URI", url);
  warc_write_header ("Content-Type", "application/http;msgtype=request");
  warc_write_date_header (timestamp_str);
  warc_write_header ("WARC-Record-ID", record_uuid);
  warc_write_ip_header (ip);
  warc_write_header ("WARC-Warcinfo-ID", warc_current_warcinfo_uuid_str);
  if (opt.warc_item_name != NULL)
    warc_write_header ("X-Wget-AT-Project-Item-Name", opt.warc_item_name);
  warc_write_digest_headers (body, payload_offset);
  warc_write_block_from_file (body);
  warc_write_end_record ();

  if (fclose (body) != 0)
    warc_write_ok = false;

  return warc_write_ok;
}

/* Writes a response record to the CDX file.
   url  is the target uri of the request/response,
   timestamp_str  is the timestamp of the request that generated this response,
                  (generated with warc_timestamp),
   mime_type  is the mime type of the response body (will be printed to CDX),
   response_code  is the HTTP response code (will be printed to CDX),
   payload_digest  is the sha1 digest of the payload,
   redirect_location  is the contents of the Location: header, or NULL (will be printed to CDX),
   offset  is the position of the WARC record in the WARC file,
   warc_filename  is the filename of the WARC,
   response_uuid  is the uuid of the response.
   Returns true on success, false on error. */
static bool
warc_write_cdx_record (const char *url, const char *timestamp_str,
                       const char *mime_type, int response_code,
                       const char *payload_digest, const char *redirect_location,
                       off_t offset, const char *warc_filename _GL_UNUSED,
                       const char *response_uuid)
{
  /* Transform the timestamp. */
  char timestamp_str_cdx[15];
  char offset_string[MAX_INT_TO_STRING_LEN(off_t)];
  const char *checksum;
  char *tmp_location = NULL;

  memcpy (timestamp_str_cdx     , timestamp_str     , 4); /* "YYYY" "-" */
  memcpy (timestamp_str_cdx +  4, timestamp_str +  5, 2); /* "mm"   "-" */
  memcpy (timestamp_str_cdx +  6, timestamp_str +  8, 2); /* "dd"   "T" */
  memcpy (timestamp_str_cdx +  8, timestamp_str + 11, 2); /* "HH"   ":" */
  memcpy (timestamp_str_cdx + 10, timestamp_str + 14, 2); /* "MM"   ":" */
  memcpy (timestamp_str_cdx + 12, timestamp_str + 17, 2); /* "SS"   "Z" */
  timestamp_str_cdx[14] = '\0';

  /* Rewrite the checksum. */
  if (payload_digest != NULL)
    checksum = payload_digest + 5; /* Skip the "sha1:" */
  else
    checksum = "-";

  if (mime_type == NULL || strlen(mime_type) == 0)
    mime_type = "-";
  if (redirect_location == NULL || strlen(redirect_location) == 0)
    tmp_location = xstrdup ("-");
  else
    tmp_location = url_escape(redirect_location);

  number_to_string (offset_string, offset);

  /* Print the CDX line. */
  if (fprintf (warc_current_cdx_file, "%s %s %s %s %d %s %s - %s %s %s\n", url,
               timestamp_str_cdx, url, mime_type, response_code, checksum,
               tmp_location, offset_string, warc_current_filename,
               response_uuid) < 0
      || fflush (warc_current_cdx_file) != 0);
    warc_write_ok = false;

  xfree (tmp_location);

  return true;
}

/* Writes a revisit record to the WARC file.
   url  is the target uri of the request/response,
   timestamp_str  is the timestamp of the request that generated this response
                  (generated with warc_timestamp),
   concurrent_to_uuid  is the uuid of the request for that generated this response
                 (generated with warc_uuid_str),
   refers_to_uuid  is the uuid of the original response
                 (generated with warc_uuid_str),
   payload_digest  is the sha1 digest of the payload,
   ip  is the ip address of the server (or NULL),
   body  is a pointer to a file containing the response headers (without payload).
   Calling this function will close body.
   Returns true on success, false on error. */
static bool
warc_write_revisit_record (const char *url, const char *timestamp_str,
                           const char *concurrent_to_uuid, const char *payload_digest,
                           const char *refers_to, const char *refers_to_target_uri,
                           const char *refers_to_date, const ip_address *ip, FILE *body)
{
  char revisit_uuid [48];
  char block_digest[BASE32_LENGTH(SHA1_DIGEST_SIZE) + 1 + 5];
  char sha1_res_block[SHA1_DIGEST_SIZE];

  warc_uuid_str (revisit_uuid, sizeof (revisit_uuid));

  sha1_stream (body, sha1_res_block);
  warc_base32_sha1_digest (sha1_res_block, block_digest, sizeof(block_digest));

  warc_write_start_record ();
  warc_write_header ("WARC-Type", "revisit");
  warc_write_header ("WARC-Record-ID", revisit_uuid);
  warc_write_header ("WARC-Warcinfo-ID", warc_current_warcinfo_uuid_str);
  warc_write_header ("WARC-Concurrent-To", concurrent_to_uuid);
  if (refers_to != "NULL")
    warc_write_header ("WARC-Refers-To", refers_to);
  if (refers_to_target_uri != NULL)
    warc_write_header ("WARC-Refers-To-Target-URI", refers_to_target_uri);
  if (refers_to_date != NULL)
    warc_write_header ("WARC-Refers-To-Date", refers_to_date);
  warc_write_header ("WARC-Profile", "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest");
  warc_write_header ("WARC-Truncated", "length");
  warc_write_header ("WARC-Target-URI", url);
  warc_write_date_header (timestamp_str);
  warc_write_ip_header (ip);
  if (opt.warc_item_name != NULL)
    warc_write_header ("X-Wget-AT-Project-Item-Name", opt.warc_item_name);
  warc_write_header ("Content-Type", "application/http;msgtype=response");
  warc_write_header ("WARC-Block-Digest", block_digest);
  warc_write_header ("WARC-Payload-Digest", payload_digest);
  warc_write_block_from_file (body);
  warc_write_end_record ();

  if (fclose (body) != 0)
    warc_write_ok = false;

  return warc_write_ok;
}

/* Writes a response record to the WARC file.
   url  is the target uri of the request/response,
   timestamp_str  is the timestamp of the request that generated this response
                  (generated with warc_timestamp),
   concurrent_to_uuid  is the uuid of the request for that generated this response
                 (generated with warc_uuid_str),
   ip  is the ip address of the server (or NULL),
   body  is a pointer to a file containing the response headers and body.
   mime_type  is the mime type of the response body (will be printed to CDX),
   response_code  is the HTTP response code (will be printed to CDX),
   redirect_location  is the contents of the Location: header, or NULL (will be printed to CDX),
   Calling this function will close body.
   Returns true on success, false on error. */
bool
warc_write_response_record (const char *url, const char *timestamp_str,
                            const char *concurrent_to_uuid, const ip_address *ip,
                            FILE *body, off_t payload_offset, const char *mime_type,
                            int response_code, const char *redirect_location)
{
  char block_digest[BASE32_LENGTH(SHA1_DIGEST_SIZE) + 1 + 5];
  char payload_digest[BASE32_LENGTH(SHA1_DIGEST_SIZE) + 1 + 5];
  char sha1_res_block[SHA1_DIGEST_SIZE];
  char sha1_res_payload[SHA1_DIGEST_SIZE];
  char response_uuid [48];
  const char *date;
  off_t offset;
  bool write_revisit;

  if (opt.warc_digests_enabled || !opt.warc_dedup_disable)
    {
      /* Calculate the block and payload digests. */
      rewind (body);

      if (warc_sha1_stream_with_payload (body, sha1_res_block, sha1_res_payload,
          payload_offset) == 0)
        {
          /* Decide (based on url + payload digest) if we have seen this
             data before. */
          struct warc_dedup_record *rec_existing;
          rec_existing = warc_find_duplicate_cdx_record (url, sha1_res_payload);

          if (rec_existing == NULL){
            warc_base32_sha1_digest (sha1_res_payload, payload_digest, sizeof(payload_digest));
            const char *revisit_cdx_date = luahooks_dedup_to_warc (url, payload_digest); 
            
            if(revisit_cdx_date != NULL) {
              rec_existing = xmalloc (sizeof (struct warc_dedup_record));

              rec_existing->uri = url;
              rec_existing->date = revisit_cdx_date;
              rec_existing->uuid = "NULL";
              memcpy (rec_existing->digest, sha1_res_payload, SHA1_DIGEST_SIZE);
            }  
          }

          if (rec_existing != NULL)
            {
              /* Check the size of the payload in case a minimum number of
                 bytes is set for the payload to deduplicate. */
              if (opt.warc_dedup_min_size > 0)
                {
                  if (fseeko (body, 0L, SEEK_END) != 0)
                    {
                      warc_write_ok = false;
                      return false;
                    }
                  offset = ftello (body);
                  if (offset < 0)
                    {
                      warc_write_ok = false;
                      return false;
                    }
                  write_revisit = ((offset - payload_offset) >= opt.warc_dedup_min_size);
                  if (fseeko (body, 0L, SEEK_SET) != 0)
                    {
                      warc_write_ok = false;
                      return false;
                    }
                }
              else
                write_revisit = true;

              /* If the payload is large enough, write a revisit record. */
              if (write_revisit)
                {
                  bool result;

                  /* Found an existing record. */
                  logprintf (LOG_VERBOSE,
              _("Found exact match in CDX file or a LUA hook. Saving revisit record to WARC.\n"));

                  /* Remove the payload from the file. */
                  if (payload_offset > 0 && ftruncate (fileno (body), payload_offset) == -1)
                    {
                      warc_write_ok = false;
                      return false;
                    }

                  /* Send the original payload digest. */
                  warc_base32_sha1_digest (sha1_res_payload, payload_digest, sizeof(payload_digest));
                  result = warc_write_revisit_record (url, timestamp_str,
                             concurrent_to_uuid, payload_digest, rec_existing->uuid,
                             rec_existing->uri, rec_existing->date, ip, body);

                  return result;
                }
            }
          warc_base32_sha1_digest (sha1_res_block, block_digest, sizeof(block_digest));
          warc_base32_sha1_digest (sha1_res_payload, payload_digest, sizeof(payload_digest));
        }
    }

  /* Not a revisit, just store the record. */

  warc_uuid_str (response_uuid, sizeof (response_uuid));

  if (fseeko (warc_current_file, 0L, SEEK_END) != 0)
    {
      warc_write_ok = false;
      return false;
    }

  offset = ftello (warc_current_file);
  if (offset < 0)
    {
      warc_write_ok = false;
      return false;
    }

  warc_write_start_record ();
  warc_write_header ("WARC-Type", "response");
  warc_write_header ("WARC-Record-ID", response_uuid);
  warc_write_header ("WARC-Warcinfo-ID", warc_current_warcinfo_uuid_str);
  warc_write_header ("WARC-Concurrent-To", concurrent_to_uuid);
  warc_write_header ("WARC-Target-URI", url);
  date = warc_write_date_header (timestamp_str);
  warc_write_ip_header (ip);
  warc_write_header ("WARC-Block-Digest", block_digest);
  warc_write_header ("WARC-Payload-Digest", payload_digest);
  if (opt.warc_item_name != NULL)
    warc_write_header ("X-Wget-AT-Project-Item-Name", opt.warc_item_name);
  warc_write_header ("Content-Type", "application/http;msgtype=response");
  warc_write_block_from_file (body);
  warc_write_end_record ();

  /* Store the WARC record in the hash table for deduplication if enabled. */
  if (!opt.warc_dedup_disable)
    store_warc_record (url, date, response_uuid, sha1_res_payload);

  if (fclose (body) != 0)
    warc_write_ok = false;

  xfree (date);

  if (warc_write_ok && opt.warc_cdx_enabled)
    {
      /* Add this record to the CDX. */
      warc_write_cdx_record (url, timestamp_str, mime_type, response_code,
      payload_digest, redirect_location, offset, warc_current_filename,
      response_uuid);
    }

  return warc_write_ok;
}

/* Writes a resource or metadata record to the WARC file.
   warc_type  is either "resource" or "metadata",
   resource_uuid  is the uuid of the resource (or NULL),
   url  is the target uri of the resource,
   timestamp_str  is the timestamp (generated with warc_timestamp),
   concurrent_to_uuid  is the uuid of the record that generated this,
   resource (generated with warc_uuid_str) or NULL,
   ip  is the ip address of the server (or NULL),
   content_type  is the mime type of the body (or NULL),
   body  is a pointer to a file containing the resource data.
   Calling this function will close body.
   Returns true on success, false on error. */
static bool
warc_write_record (const char *record_type, const char *resource_uuid,
                 const char *url, const char *timestamp_str,
                 const char *concurrent_to_uuid,
                 const ip_address *ip, const char *content_type, FILE *body,
                 off_t payload_offset)
{
  char uuid_buf[48];

  if (resource_uuid == NULL)
    {
      warc_uuid_str (uuid_buf, sizeof (uuid_buf));
      resource_uuid = uuid_buf;
    }

  if (content_type == NULL)
    content_type = "application/octet-stream";

  warc_write_start_record ();
  warc_write_header ("WARC-Type", record_type);
  warc_write_header ("WARC-Record-ID", resource_uuid);
  warc_write_header ("WARC-Warcinfo-ID", warc_current_warcinfo_uuid_str);
  warc_write_header ("WARC-Concurrent-To", concurrent_to_uuid);
  warc_write_header ("WARC-Target-URI", url);
  warc_write_date_header (timestamp_str);
  warc_write_ip_header (ip);
  warc_write_digest_headers (body, payload_offset);
  warc_write_header ("Content-Type", content_type);
  warc_write_block_from_file (body);
  warc_write_end_record ();

  if (fclose (body) != 0)
    warc_write_ok = false;

  return warc_write_ok;
}

/* Writes a resource record to the WARC file.
   resource_uuid  is the uuid of the resource (or NULL),
   url  is the target uri of the resource,
   timestamp_str  is the timestamp (generated with warc_timestamp),
   concurrent_to_uuid  is the uuid of the record that generated this,
   resource (generated with warc_uuid_str) or NULL,
   ip  is the ip address of the server (or NULL),
   content_type  is the mime type of the body (or NULL),
   body  is a pointer to a file containing the resource data.
   Calling this function will close body.
   Returns true on success, false on error. */
bool
warc_write_resource_record (const char *resource_uuid, const char *url,
                 const char *timestamp_str, const char *concurrent_to_uuid,
                 const ip_address *ip, const char *content_type, FILE *body,
                 off_t payload_offset)
{
  return warc_write_record ("resource",
      resource_uuid, url, timestamp_str, concurrent_to_uuid,
      ip, content_type, body, payload_offset);
}

/* Writes a metadata record to the WARC file.
   record_uuid  is the uuid of the record (or NULL),
   url  is the target uri of the record,
   timestamp_str  is the timestamp (generated with warc_timestamp),
   concurrent_to_uuid  is the uuid of the record that generated this,
   record (generated with warc_uuid_str) or NULL,
   ip  is the ip address of the server (or NULL),
   content_type  is the mime type of the body (or NULL),
   body  is a pointer to a file containing the record data.
   Calling this function will close body.
   Returns true on success, false on error. */
bool
warc_write_metadata_record (const char *record_uuid, const char *url,
                 const char *timestamp_str, const char *concurrent_to_uuid,
                 ip_address *ip, const char *content_type, FILE *body,
                 off_t payload_offset)
{
  return warc_write_record ("metadata",
      record_uuid, url, timestamp_str, concurrent_to_uuid,
      ip, content_type, body, payload_offset);
}