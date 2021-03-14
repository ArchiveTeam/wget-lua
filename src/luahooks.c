#define _GNU_SOURCE

#include "wget.h"
#include "http.h"
#include "url.h"
#include "convert.h"
#include "iri.h"
#include "recur.h"
#include "exits.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "luahooks.h"

#define LUA_PUSH_TO_TABLE(TYPE, KEY, VALUE) \
    lua_push ## TYPE (lua, VALUE); \
    lua_setfield (lua, -2, KEY);


static lua_State *lua;

static luahook_action_t
string_to_luahook_action (const char * s)
{
#define CONST_CASE(KEY) if (strcmp (s, #KEY) == 0) return KEY;
  if (s == NULL) return LUAHOOK_NOTHING;
  CONST_CASE (LUAHOOK_NOTHING);
  CONST_CASE (LUAHOOK_CONTINUE);
  CONST_CASE (LUAHOOK_EXIT);
  CONST_CASE (LUAHOOK_ABORT);
  return LUAHOOK_NOTHING;
#undef CONST_CASE
}

static luahook_action_t
integer_to_luahook_action (int a)
{
  switch (a)
  {
    case LUAHOOK_NOTHING:
    case LUAHOOK_CONTINUE:
    case LUAHOOK_EXIT:
    case LUAHOOK_ABORT:
      return (luahook_action_t)a;
  }
  return LUAHOOK_NOTHING;
}

static void
luahooks_push_integer_to_table (const char *key, int value)
{
  LUA_PUSH_TO_TABLE (integer, key, value);
}

static void
luahooks_push_number_to_table (const char *key, double value)
{
  LUA_PUSH_TO_TABLE (number, key, value);
}

static void
luahooks_push_string_to_table (const char *key, const char *value)
{
  LUA_PUSH_TO_TABLE (string, key, value);
}

static void
luahooks_push_boolean_to_table (const char *key, bool value)
{
  LUA_PUSH_TO_TABLE (boolean, key, value);
}

static void
handle_lua_error (int res)
{
  if (res != 0)
    {
      char *msg;
      msg = strdup (lua_tostring (lua, -1));
      lua_pop (lua, 1);
      switch (res)
        {
          case LUA_ERRRUN:
            printf ("Lua runtime error: %s.\n", msg);
            break;
          case LUA_ERRSYNTAX:
            printf ("Lua syntax error: %s.\n", msg);
            break;
          case LUA_ERRMEM:
            printf ("Lua memory allocation error: %s.\n", msg);
            break;
          case LUA_ERRERR:
            printf ("Lua error handling error: %s.\n", msg);
            break;
          case LUA_ERRFILE:
            printf ("Lua cannot load file: %s.\n", msg);
            break;
          default:
            printf ("Lua error: %s.\n", msg);
        }
      free (msg);
      if (!opt.no_abort_on_lua_error)
        {
            fflush(stdout);
            abort();
        }
    }
}

bool
luahooks_function_lookup (const char *type, const char *name)
{
  lua_getglobal (lua, "wget");
  if (! lua_istable (lua, -1))
    {
      lua_pop (lua, 1);
      return false;
    }

  lua_getfield (lua, -1, type);
  /* Remove wget from the stack. */
  lua_remove (lua, -2);
  if (! lua_istable (lua, -1))
    {
      lua_pop (lua, 1);
      return false;
    }

  lua_getfield (lua, -1, name);
  /* Remove type from the stack. */
  lua_remove (lua, -2);
  if (! lua_isfunction (lua, -1))
    {
      lua_pop (lua, 1);
      return false;
    }

  return true;
}

void
luahooks_init ()
{
  if (opt.lua_filename == NULL)
    return;

  lua = lua_open ();
  luaL_openlibs (lua);

  /* Initialize constants. */
  lua_newtable (lua);

  lua_newtable (lua);
  lua_setfield (lua, -2, "callbacks");

  lua_newtable (lua);
  LUA_PUSH_TO_TABLE (integer, "NOTHING", LUAHOOK_NOTHING);
  LUA_PUSH_TO_TABLE (integer, "CONTINUE", LUAHOOK_CONTINUE);
  LUA_PUSH_TO_TABLE (integer, "EXIT", LUAHOOK_EXIT);
  LUA_PUSH_TO_TABLE (integer, "ABORT", LUAHOOK_ABORT);
  lua_setfield (lua, -2, "actions");

  lua_newtable (lua);
  LUA_PUSH_TO_TABLE (integer, "SUCCESS", WGET_EXIT_SUCCESS);
  LUA_PUSH_TO_TABLE (integer, "GENERIC_ERROR", WGET_EXIT_GENERIC_ERROR);
  LUA_PUSH_TO_TABLE (integer, "PARSE_ERROR", WGET_EXIT_PARSE_ERROR);
  LUA_PUSH_TO_TABLE (integer, "IO_FAIL", WGET_EXIT_IO_FAIL);
  LUA_PUSH_TO_TABLE (integer, "NETWORK_FAIL", WGET_EXIT_NETWORK_FAIL);
  LUA_PUSH_TO_TABLE (integer, "SSL_AUTH_FAIL", WGET_EXIT_SSL_AUTH_FAIL);
  LUA_PUSH_TO_TABLE (integer, "SERVER_AUTH_FAIL", WGET_EXIT_SERVER_AUTH_FAIL);
  LUA_PUSH_TO_TABLE (integer, "PROTOCOL_ERROR", WGET_EXIT_PROTOCOL_ERROR);
  LUA_PUSH_TO_TABLE (integer, "SERVER_ERROR", WGET_EXIT_SERVER_ERROR);
  LUA_PUSH_TO_TABLE (integer, "UNKNOWN", WGET_EXIT_UNKNOWN);
  lua_setfield (lua, -2, "exits");

  lua_setglobal (lua, "wget");

  int res = luaL_dofile (lua, opt.lua_filename);
  if (res != 0)
    handle_lua_error (res);

  if (luahooks_function_lookup ("callbacks", "init"))
    {
      int res = lua_pcall (lua, 0, 0, 0);
      if (res != 0)
        handle_lua_error (res);
    }

/*
  int i;
  for (i=0; i<5; i++)
    {
      lua_getfield (lua, LUA_GLOBALSINDEX, "test");
      lua_pushinteger (lua, i);
      int res = lua_pcall (lua, 1, 0, 0);

    }

  lua_close (lua);
*/
}

#define CONST_CASE(KEY) case KEY : return #KEY ;

static char *
uerr_to_string (const uerr_t v)
{
  switch (v)
    {
      CONST_CASE (NOCONERROR)
      CONST_CASE (HOSTERR)
      CONST_CASE (CONSOCKERR)
      CONST_CASE (CONERROR)
      CONST_CASE (CONSSLERR)
      CONST_CASE (CONIMPOSSIBLE)
      CONST_CASE (NEWLOCATION)
      CONST_CASE (FTPOK)
      CONST_CASE (FTPLOGINC)
      CONST_CASE (FTPLOGREFUSED)
      CONST_CASE (FTPPORTERR)
      CONST_CASE (FTPSYSERR)
      CONST_CASE (FTPNSFOD)
      CONST_CASE (FTPUNKNOWNTYPE)
      CONST_CASE (FTPRERR)
      CONST_CASE (FTPSRVERR)
      CONST_CASE (FTPRETRINT)
      CONST_CASE (FTPRESTFAIL)
      CONST_CASE (URLERROR)
      CONST_CASE (FOPENERR)
      CONST_CASE (FOPEN_EXCL_ERR)
      CONST_CASE (FWRITEERR)
      CONST_CASE (HEOF)
      CONST_CASE (GATEWAYTIMEOUT)
      CONST_CASE (HERR)
      CONST_CASE (RETROK)
      CONST_CASE (RECLEVELEXC)
      CONST_CASE (WRONGCODE)
      CONST_CASE (FTPINVPASV)
      CONST_CASE (FTPNOPASV)
      CONST_CASE (FTPNOPBSZ)
      CONST_CASE (FTPNOPROT)
      CONST_CASE (FTPNOAUTH)
      CONST_CASE (CONTNOTSUPPORTED)
      CONST_CASE (RETRUNNEEDED)
      CONST_CASE (RETRFINISHED)
      CONST_CASE (READERR)
      CONST_CASE (TRYLIMEXC)
      CONST_CASE (FILEBADFILE)
      CONST_CASE (RANGEERR)
      CONST_CASE (RETRBADPATTERN)
      CONST_CASE (PROXERR)
      CONST_CASE (AUTHFAILED)
      CONST_CASE (QUOTEXC)
      CONST_CASE (WRITEFAILED)
      CONST_CASE (SSLINITFAILED)
      CONST_CASE (VERIFCERTERR)
      CONST_CASE (UNLINKERR)
      CONST_CASE (NEWLOCATION_KEEP_POST)
      CONST_CASE (CLOSEFAILED)
      CONST_CASE (ATTRMISSING)
      CONST_CASE (UNKNOWNATTR)
      CONST_CASE (WARC_ERR)
      CONST_CASE (WARC_TMP_FOPENERR)
      CONST_CASE (WARC_TMP_FWRITEERR)
      CONST_CASE (TIMECONV_ERR)
      CONST_CASE (METALINK_PARSE_ERROR)
      CONST_CASE (METALINK_RETR_ERROR)
      CONST_CASE (METALINK_CHKSUM_ERROR)
      CONST_CASE (METALINK_SIG_ERROR)
      CONST_CASE (METALINK_MISSING_RESOURCE)
      CONST_CASE (RETR_WITH_METALINK)
    }
  return NULL;
}

static char *
url_scheme_to_string (const enum url_scheme v)
{
  switch (v)
    {
      CONST_CASE (SCHEME_HTTP)
#ifdef HAVE_SSL
      CONST_CASE (SCHEME_HTTPS)
#endif
      CONST_CASE (SCHEME_FTP)
      CONST_CASE (SCHEME_INVALID)
    }
  return NULL;
}

static char *
reject_reason_to_string (const reject_reason v)
{
  switch (v)
    {
      CONST_CASE (WG_RR_SUCCESS)
      CONST_CASE (WG_RR_BLACKLIST)
      CONST_CASE (WG_RR_NOTHTTPS)
      CONST_CASE (WG_RR_NONHTTP)
      CONST_CASE (WG_RR_ABSOLUTE)
      CONST_CASE (WG_RR_DOMAIN)
      CONST_CASE (WG_RR_PARENT)
      CONST_CASE (WG_RR_LIST)
      CONST_CASE (WG_RR_REGEX)
      CONST_CASE (WG_RR_RULES)
      CONST_CASE (WG_RR_SPANNEDHOST)
      CONST_CASE (WG_RR_ROBOTS)
      CONST_CASE (WG_RR_LUAHOOK)
    }
  return NULL;
}

/* For backward compatibility. */
static char *
reject_reason_to_download_child_p_string (const reject_reason v)
{
  switch (v)
    {
      case WG_RR_SUCCESS:     return NULL;
      case WG_RR_BLACKLIST:   return "ALREADY_ON_BLACKLIST";
      case WG_RR_NOTHTTPS:    return "NOT_HTTPS_SCHEME";
      case WG_RR_NONHTTP:     return "NON_HTTP_SCHEME";
      case WG_RR_ABSOLUTE:    return "NOT_A_RELATIVE_LINK";
      case WG_RR_DOMAIN:      return "DOMAIN_NOT_ACCEPTED";
      case WG_RR_PARENT:      return "IN_PARENT_DIRECTORY";
      case WG_RR_LIST:        return "DIRECTORY_EXCLUDED";
      case WG_RR_REGEX:       return "REGEX_EXCLUDED";
      case WG_RR_RULES:       return "PATTERN_EXCLUDED";
      case WG_RR_SPANNEDHOST: return "DIFFERENT_HOST";
      case WG_RR_ROBOTS:      return "ROBOTS_TXT_FORBIDDEN";
      case WG_RR_LUAHOOK:     return "LUAHOOK";
    }
  return NULL;
}

static char *
exit_status_to_string (const int v)
{
  switch (v)
    {
      case WGET_EXIT_SUCCESS: return "SUCCESS";
      case WGET_EXIT_GENERIC_ERROR: return "GENERIC_ERROR";
      case WGET_EXIT_PARSE_ERROR: return "PARSE_ERROR";
      case WGET_EXIT_IO_FAIL: return "IO_FAIL";
      case WGET_EXIT_NETWORK_FAIL: return "NETWORK_FAIL";
      case WGET_EXIT_SSL_AUTH_FAIL: return "SSL_AUTH_FAIL";
      case WGET_EXIT_SERVER_AUTH_FAIL: return "SERVER_AUTH_FAIL";
      case WGET_EXIT_PROTOCOL_ERROR: return "PROTOCOL_ERROR";
      case WGET_EXIT_SERVER_ERROR: return "SERVER_ERROR";
      case WGET_EXIT_UNKNOWN: return "UNKNOWN";
    }
  return NULL;
}

#undef CONST_CASE

#define LUA_PUSH_FROM_STRUCT(TYPE, STRUCT, FIELD) \
  luahooks_push_ ## TYPE ## _to_table (#FIELD, STRUCT->FIELD);

static void
http_stat_to_lua_table (const struct http_stat *hs)
{
  if (hs == NULL)
    {
      lua_pushnil (lua);
    }
  else
    {
      /* Create a table for 18 elements. */
      lua_createtable (lua, 0, 18);
      LUA_PUSH_FROM_STRUCT (integer, hs, len);
      LUA_PUSH_FROM_STRUCT (integer, hs, contlen);
      LUA_PUSH_FROM_STRUCT (integer, hs, restval);
      LUA_PUSH_FROM_STRUCT (integer, hs, res);
      LUA_PUSH_FROM_STRUCT (string,  hs, rderrmsg);
      LUA_PUSH_FROM_STRUCT (string,  hs, newloc);
      LUA_PUSH_FROM_STRUCT (string,  hs, remote_time);
      LUA_PUSH_FROM_STRUCT (string,  hs, error);
      LUA_PUSH_FROM_STRUCT (integer, hs, statcode);
      LUA_PUSH_FROM_STRUCT (string,  hs, message);
      LUA_PUSH_FROM_STRUCT (integer, hs, rd_size);
      LUA_PUSH_FROM_STRUCT (number,  hs, dltime);
      LUA_PUSH_FROM_STRUCT (string,  hs, referer);
      LUA_PUSH_FROM_STRUCT (string,  hs, local_file);
      LUA_PUSH_FROM_STRUCT (boolean, hs, existence_checked);
      LUA_PUSH_FROM_STRUCT (boolean, hs, timestamp_checked);
      LUA_PUSH_FROM_STRUCT (string,  hs, orig_file_name);
      LUA_PUSH_FROM_STRUCT (integer, hs, orig_file_size);
      /* TODO add orig_file_tstamp for completeness? */
    }
}

static void
url_to_lua_table (const struct url *u)
{
  if (u == NULL)
    {
      lua_pushnil (lua);
    }
  else
    {
      /* Create a table for 12 elements. */
      lua_createtable (lua, 0, 12);
      LUA_PUSH_FROM_STRUCT (string,  u, url);
      luahooks_push_string_to_table ("scheme", url_scheme_to_string (u->scheme));
      LUA_PUSH_FROM_STRUCT (string,  u, host);
      LUA_PUSH_FROM_STRUCT (integer, u, port);
      LUA_PUSH_FROM_STRUCT (string,  u, path);
      LUA_PUSH_FROM_STRUCT (string,  u, params);
      LUA_PUSH_FROM_STRUCT (string,  u, query);
      LUA_PUSH_FROM_STRUCT (string,  u, fragment);
      LUA_PUSH_FROM_STRUCT (string,  u, dir);
      LUA_PUSH_FROM_STRUCT (string,  u, file);
      LUA_PUSH_FROM_STRUCT (string,  u, user);
      LUA_PUSH_FROM_STRUCT (string,  u, passwd);
    }
}

static void
urlpos_to_lua_table (const struct urlpos *upos)
{
  if (upos == NULL)
    {
      lua_pushnil (lua);
    }
  else
    {
      /* Create a table for 10 elements. */
      lua_createtable (lua, 0, 10);
      url_to_lua_table (upos->url);
      lua_setfield (lua, -2, "url");
      LUA_PUSH_FROM_STRUCT (string,  upos, local_name);
      LUA_PUSH_FROM_STRUCT (integer, upos, ignore_when_downloading);
      LUA_PUSH_FROM_STRUCT (integer, upos, link_relative_p);
      LUA_PUSH_FROM_STRUCT (integer, upos, link_complete_p);
      LUA_PUSH_FROM_STRUCT (integer, upos, link_base_p);
      LUA_PUSH_FROM_STRUCT (integer, upos, link_inline_p);
      LUA_PUSH_FROM_STRUCT (integer, upos, link_css_p);
      LUA_PUSH_FROM_STRUCT (integer, upos, link_expect_html);
      LUA_PUSH_FROM_STRUCT (integer, upos, link_expect_css);
      LUA_PUSH_FROM_STRUCT (integer, upos, link_refresh_p);
    }
}

static void
iri_to_lua_table (const struct iri *i)
{
  if (i == NULL)
    {
      lua_pushnil (lua);
    }
  else
    {
      /* Create a table for 4 elements. */
      lua_createtable (lua, 0, 4);
      LUA_PUSH_FROM_STRUCT (string,  i, uri_encoding);
      LUA_PUSH_FROM_STRUCT (string,  i, content_encoding);
      LUA_PUSH_FROM_STRUCT (string,  i, orig_url);
      LUA_PUSH_FROM_STRUCT (boolean,  i, utf8_encode);
    }
}

#undef LUA_PUSH_FROM_STRUCT

#define MAX_HOST_LENGTH 255
/* luahooks_lookup_host reuses this buffer for each response. */
static char lookup_host_result[MAX_HOST_LENGTH + 1];

const char *
luahooks_lookup_host (const char *host)
{
  if (lua == NULL || !luahooks_function_lookup ("callbacks", "lookup_host"))
    return NULL;

  lua_pushstring (lua, host);

  int res = lua_pcall (lua, 1, 1, 0);
  if (res != 0)
    {
      handle_lua_error (res);
      return NULL;
    }
  else
    {
      /* The lookup_host function can return an alternative hostname or IP. */
      const char *ret = lua_tostring (lua, -1);
      if (ret == NULL)
        return NULL;

      /* Copy to the buffer. */
      size_t ret_l = lua_strlen(lua, -1) + 1;
      ret_l = (ret_l <= MAX_HOST_LENGTH) ? ret_l : MAX_HOST_LENGTH;
      strncpy (lookup_host_result, ret, ret_l);

      lua_pop (lua, 1);
      return lookup_host_result;
    }
}
#undef MAX_HOST_LENGTH

luahook_action_t
luahooks_httploop_result (const struct url *url, const uerr_t err, const struct http_stat *hstat)
{
  if (lua == NULL || !luahooks_function_lookup ("callbacks", "httploop_result"))
    return LUAHOOK_NOTHING;

  url_to_lua_table (url);
  lua_pushstring (lua, uerr_to_string (err));
  http_stat_to_lua_table (hstat);

  int res = lua_pcall (lua, 3, 1, 0);
  if (res != 0)
    {
      handle_lua_error (res);
      return LUAHOOK_NOTHING;
    }
  else
    {
      int answer = lua_tointeger (lua, -1);
      luahook_action_t action = integer_to_luahook_action (answer);
      lua_pop (lua, 1);
      return action;
    }
}

bool
luahooks_write_to_warc (const struct url *url, const struct http_stat *hstat)
{
  if (lua == NULL || !luahooks_function_lookup ("callbacks", "write_to_warc"))
    return true;

  url_to_lua_table (url);
  http_stat_to_lua_table (hstat);

  int res = lua_pcall (lua, 2, 1, 0);
  if (res != 0)
    {
      handle_lua_error (res);
      return true;
    }
  else
    {
      bool answer = lua_toboolean (lua, -1);
      lua_pop (lua, 1);
      return answer;
    }
}

bool
luahooks_download_child (const struct urlpos *upos, struct url *parent, int depth,
                         struct url *start_url_parsed, struct iri *iri,
                         reject_reason reason)
{
  bool verdict = (reason == WG_RR_SUCCESS);
  const char *reason_string;
  if (lua == NULL)
    return verdict;
  else if (luahooks_function_lookup ("callbacks", "download_child"))
    /* New function. */
    reason_string = reject_reason_to_string (reason);
  else if (luahooks_function_lookup ("callbacks", "download_child_p"))
    /* Old function, map to old string. */
    reason_string = reject_reason_to_download_child_p_string (reason);
  else
    return verdict;

  urlpos_to_lua_table (upos);
  url_to_lua_table (parent);
  lua_pushinteger (lua, depth);
  url_to_lua_table (start_url_parsed);
  iri_to_lua_table (iri);
  lua_pushboolean (lua, verdict);
  lua_pushstring (lua, reason_string);

  int res = lua_pcall (lua, 7, 1, 0);
  if (res != 0)
    {
      handle_lua_error (res);
      return verdict;
    }
  else
    {
      bool answer = lua_toboolean (lua, -1);
      lua_pop (lua, 1);
      return answer;
    }
}

bool
luahooks_can_generate_urls ()
{
  if (lua == NULL || !luahooks_function_lookup ("callbacks", "get_urls"))
    return false;
  lua_pop (lua, 1);
  return true;
}

struct luahooks_url *
luahooks_get_urls (const char *file, const char *url, bool is_css,
                   struct iri *iri)
{
  if (lua == NULL || !luahooks_function_lookup ("callbacks", "get_urls"))
    return NULL;

  lua_pushstring (lua, file);
  lua_pushstring (lua, url);
  lua_pushboolean (lua, is_css);
  iri_to_lua_table (iri);

  int res = lua_pcall (lua, 4, 1, 0);
  if (res != 0)
    {
      handle_lua_error (res);
      return NULL;
    }
  else
    {
      struct luahooks_url *head = NULL;
      struct luahooks_url *cur;
      if (lua_istable (lua, -1))
        {
          /* The first key. */
          lua_pushnil (lua);
          while (lua_next (lua, -2) != 0)
            {
              /* Value should be a table. */

              const char *ret;

              lua_getfield (lua, -1, "url");
              ret = lua_tostring (lua, -1);

              if (ret)
                {
                  cur = malloc (sizeof (struct luahooks_url));

                  cur->url = strdup (ret);
                  lua_pop (lua, 1);

                  lua_getfield (lua, -1, "link_expect_html");
                  cur->link_expect_html = lua_tointeger (lua, -1) == 1 ? 1 : 0;
                  lua_pop (lua, 1);

                  lua_getfield (lua, -1, "link_expect_css");
                  cur->link_expect_css = lua_tointeger (lua, -1) == 1 ? 1 : 0;
                  lua_pop (lua, 1);

                  cur->body_data = NULL;
                  cur->method = NULL;

                  lua_getfield (lua, -1, "post_data");
                  ret = lua_tostring (lua, -1);
                  lua_pop (lua, 1);
                  if (ret)
                    {
                      cur->body_data = strdup (ret);
                      cur->method = strdup ("POST");
                    }

                  lua_getfield (lua, -1, "body_data");
                  ret = lua_tostring (lua, -1);
                  lua_pop (lua, 1);
                  if (ret)
                    cur->body_data = strdup (ret);

                  lua_getfield (lua, -1, "method");
                  ret = lua_tostring (lua, -1);
                  lua_pop (lua, 1);
                  if (ret)
                    cur->method = strdup (ret);

                  struct luahooks_url_header *header_head = NULL;
                  lua_getfield (lua, -1, "headers");
                  if (lua_istable (lua, -1))
                    {
                      struct luahooks_url_header *header_cur;

                      lua_pushnil (lua);
                      while (lua_next (lua, -2) != 0)
                        {
                          header_cur = malloc (sizeof (struct luahooks_url_header));

                          header_cur->key = NULL;
                          header_cur->value = NULL;

                          ret = lua_tostring (lua, -2);
                          if (ret)
                            header_cur->key = strdup (ret);

                          ret = lua_tostring (lua, -1);
                          if (ret)
                            header_cur->value = strdup (ret);

                          header_cur->next = header_head;
                          header_head = header_cur;

                          lua_pop (lua, 1);
                        }
                    }
                  lua_pop (lua, 1);

                  cur->headers = header_head;

                  cur->next = head;
                  head = cur;
                }

              /* Remove value, keep key for next iteration. */
              lua_pop (lua, 1);
            }
        }
      /* Remove table. */
      lua_pop (lua, 1);
      return head;
    }
}

void
luahooks_finish (double start_time, double end_time,
                 int numurls, SUM_SIZE_INT total_downloaded_bytes,
                 double total_download_time)
{
  if (lua == NULL || !luahooks_function_lookup ("callbacks", "finish"))
    return;

  lua_pushnumber (lua, start_time);
  lua_pushnumber (lua, end_time);
  lua_pushnumber (lua, (end_time - start_time));
  lua_pushinteger (lua, numurls);
  /* Push the number of downloaded bytes as a double.  */
  lua_pushnumber (lua, total_downloaded_bytes);
  lua_pushnumber (lua, total_download_time);

  int res = lua_pcall (lua, 6, 0, 0);
  if (res != 0)
    {
      handle_lua_error (res);
    }
}

int
luahooks_before_exit (int exit_status)
{
  if (lua == NULL || !luahooks_function_lookup ("callbacks", "before_exit"))
    return exit_status;

  lua_pushinteger (lua, exit_status);
  lua_pushstring (lua, exit_status_to_string (exit_status));

  int res = lua_pcall (lua, 2, 1, 0);
  if (res != 0)
    {
      handle_lua_error (res);
      return exit_status;
    }
  else
    {
      int answer = lua_tointeger (lua, -1);
      lua_pop (lua, 1);
      return answer;
    }
}

