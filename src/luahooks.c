#define _GNU_SOURCE

#include "wget.h"
#include "http.h"
#include "url.h"
#include "convert.h"
#include "iri.h"

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
      CONST_CASE (NOTENOUGHMEM)
      CONST_CASE (CONPORTERR)
      CONST_CASE (CONCLOSED)
      CONST_CASE (FTPOK)
      CONST_CASE (FTPLOGINC)
      CONST_CASE (FTPLOGREFUSED)
      CONST_CASE (FTPPORTERR)
      CONST_CASE (FTPSYSERR)
      CONST_CASE (FTPNSFOD)
      CONST_CASE (FTPRETROK)
      CONST_CASE (FTPUNKNOWNTYPE)
      CONST_CASE (FTPRERR)
      CONST_CASE (FTPREXC)
      CONST_CASE (FTPSRVERR)
      CONST_CASE (FTPRETRINT)
      CONST_CASE (FTPRESTFAIL)
      CONST_CASE (URLERROR)
      CONST_CASE (FOPENERR)
      CONST_CASE (FOPEN_EXCL_ERR)
      CONST_CASE (FWRITEERR)
      CONST_CASE (HOK)
      CONST_CASE (HLEXC)
      CONST_CASE (HEOF)
      CONST_CASE (HERR)
      CONST_CASE (RETROK)
      CONST_CASE (RECLEVELEXC)
      CONST_CASE (FTPACCDENIED)
      CONST_CASE (WRONGCODE)
      CONST_CASE (FTPINVPASV)
      CONST_CASE (FTPNOPASV)
      CONST_CASE (CONTNOTSUPPORTED)
      CONST_CASE (RETRUNNEEDED)
      CONST_CASE (RETRFINISHED)
      CONST_CASE (READERR)
      CONST_CASE (TRYLIMEXC)
      CONST_CASE (URLBADPATTERN)
      CONST_CASE (FILEBADFILE)
      CONST_CASE (RANGEERR)
      CONST_CASE (RETRBADPATTERN)
      CONST_CASE (RETNOTSUP)
      CONST_CASE (ROBOTSOK)
      CONST_CASE (NOROBOTS)
      CONST_CASE (PROXERR)
      CONST_CASE (AUTHFAILED)
      CONST_CASE (QUOTEXC)
      CONST_CASE (WRITEFAILED)
      CONST_CASE (SSLINITFAILED)
      CONST_CASE (VERIFCERTERR)
      CONST_CASE (UNLINKERR)
      CONST_CASE (NEWLOCATION_KEEP_POST)
      CONST_CASE (WARC_ERR)
      CONST_CASE (WARC_TMP_FOPENERR)
      CONST_CASE (WARC_TMP_FWRITEERR)
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
luahooks_download_child_p (const struct urlpos *upos, struct url *parent, int depth,
                           struct url *start_url_parsed, struct iri *iri,
                           bool verdict)
{
  if (lua == NULL || !luahooks_function_lookup ("callbacks", "download_child_p"))
    return verdict;

  urlpos_to_lua_table (upos);
  url_to_lua_table (parent);
  lua_pushinteger (lua, depth);
  url_to_lua_table (start_url_parsed);
  iri_to_lua_table (iri);
  lua_pushboolean (lua, verdict);

  int res = lua_pcall (lua, 6, 1, 0);
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

