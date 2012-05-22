dofile("table_show.lua")

wget.callbacks.init = function()
  print(table.show({}, "init"))
end

wget.callbacks.httploop_result = function(url, err, http_stat)
  print(table.show({url=url, err=err, http_stat=http_stat }, "httploop_result"))
  return wget.actions.NOTHING
end

wget.callbacks.download_child_p = function(urlpos, parent, depth, start_url_parsed, iri, verdict)
  print(table.show({urlpos=urlpos, parent=parent, depth=depth, start_url_parsed=start_url_parsed, iri=iri, verdict=verdict}, "download_child_p"))
  return verdict
end

wget.callbacks.get_urls = function(file, url, is_css, iri)
  print(table.show({file=file, url=url, is_css=is_css, iri=iri}, "get_urls"))

  if string.find(url, "test") then
    return {}
  else
    return {
      { url=url.."/test/",
        link_expect_html=1,
        link_expect_css=0 }
    }
  end
end

