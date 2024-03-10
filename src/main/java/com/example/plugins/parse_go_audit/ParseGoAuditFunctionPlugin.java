package com.example.plugins.parse_go_audit;

import org.graylog2.plugin.Plugin;
import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.PluginModule;

import java.util.Collection;
import java.util.Collections;

public class ParseGoAuditFunctionPlugin implements Plugin {
    @Override
    public PluginMetaData metadata() {
        return new ParseGoAuditFunctionMetaData();
    }

    @Override
    public Collection<PluginModule> modules () {
        return Collections.<PluginModule>singletonList(new ParseGoAuditFunctionModule());
    }
}