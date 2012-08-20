#ifndef LUAHOOKS_H
#define LUAHOOKS_H

#include "wget.h"
#include "http.h"

typedef enum 
{
  LUAHOOK_NOTHING,
  LUAHOOK_CONTINUE,
  LUAHOOK_EXIT,
  LUAHOOK_ABORT
} luahook_action_t;

struct luahooks_url
{
  const char *url;
  unsigned int link_expect_html;
  unsigned int link_expect_css;
  char *post_data;
  struct luahooks_url *next;
};

void luahooks_init ();
luahook_action_t luahooks_httploop_result (const struct url *url,
                    const uerr_t err, const struct http_stat *hstat);
bool luahooks_download_child_p (const struct urlpos *upos,
                    struct url *parent, int depth,
                    struct url *start_url_parsed, struct iri *iri,
                    bool verdict);
bool luahooks_can_generate_urls ();
struct luahooks_url *luahooks_get_urls (const char *file, const char *url,
                                       bool is_css, struct iri *iri);

#endif /* LUAHOOKS_H */

