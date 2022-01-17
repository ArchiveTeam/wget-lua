/* Declarations of WARC helper methods. */
#ifndef WARC_H
#define WARC_H

#include "host.h"

void warc_init (void);
void warc_close (void);
void warc_uuid_str (char *id_str);

char * warc_timestamp (char *timestamp, size_t timestamp_size);

FILE * warc_tempfile (void);

int warc_sha1_stream_with_payload (FILE *stream, void *res_block, void *res_payload, 
  off_t payload_offset);
char * warc_base32_sha1_digest (const char *sha1_digest, char *sha1_base32, 
  size_t sha1_base32_size);
bool warc_write_request_record (const char *url, const char *timestamp_str,
  const char *concurrent_to_uuid, const ip_address *ip, FILE *body, off_t payload_offset);
bool warc_write_response_record (const char *url, const char *timestamp_str,
  const char *concurrent_to_uuid, const ip_address *ip, FILE *body, off_t payload_offset,
  const char *mime_type, int response_code, const char *redirect_location);
bool warc_write_resource_record (const char *resource_uuid, const char *url,
  const char *timestamp_str, const char *concurrent_to_uuid, const ip_address *ip,
  const char *content_type, FILE *body, off_t payload_offset);
bool warc_write_metadata_record (const char *record_uuid, const char *url,
  const char *timestamp_str, const char *concurrent_to_uuid, ip_address *ip,
  const char *content_type, FILE *body, off_t payload_offset);
bool warc_write_arbitrary_revisit_record (const char *url, const char *timestamp_str,
  const char *concurrent_to_uuid, const char *payload_digest,
  const char *refers_to_target_uri, const ip_address *ip, FILE *body);
                               

#endif /* WARC_H */
