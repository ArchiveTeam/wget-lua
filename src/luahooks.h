#ifndef LUAHOOKS_H
#define LUAHOOKS_H

#include "wget.h"
#include "http.h"
#include "recur.h"

typedef enum 
{
  LUAHOOK_NOTHING,
  LUAHOOK_CONTINUE,
  LUAHOOK_EXIT,
  LUAHOOK_ABORT
} luahook_action_t;

struct luahooks_url_header
{
  char *key;
  char *value;
  struct luahooks_url_header *next;
};

struct luahooks_url
{
  const char *url;
  unsigned int link_expect_html;
  unsigned int link_expect_css;
  char *body_data;
  char *method;
  struct luahooks_url_header *headers;
  struct luahooks_url *next;
};

void luahooks_init ();
const char *luahooks_lookup_host (const char *host);
luahook_action_t luahooks_httploop_result (const struct url *url,
                    const uerr_t err, const struct http_stat *hstat);
bool luahooks_write_to_warc (const struct url *url, const struct http_stat *hstat);
const char *luahooks_dedup_to_warc (const char *url, char *digest);
bool luahooks_download_child (const struct urlpos *upos,
                    struct url *parent, int depth,
                    struct url *start_url_parsed, struct iri *iri,
                    reject_reason reason);
bool luahooks_can_generate_urls ();
struct luahooks_url *luahooks_get_urls (const char *file, const char *url,
                                       bool is_css, struct iri *iri);
void luahooks_finish (double start_time, double end_time,
                 int numurls, SUM_SIZE_INT total_downloaded_bytes,
                 double total_download_time);
int luahooks_before_exit (int exit_status);

#endif /* LUAHOOKS_H */

