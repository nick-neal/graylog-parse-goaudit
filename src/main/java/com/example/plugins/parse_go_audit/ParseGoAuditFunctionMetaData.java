package com.example.plugins.parse_go_audit;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

public class ParseGoAuditFunctionMetaData implements PluginMetaData {
    private static final String PLUGIN_PROPERTIES = "com.example.plugins.graylog-plugin-function-parse-go-audit/graylog-plugin.properties";

    @Override
    public String getUniqueId() {
        return "com.example.plugins.parse_go_audit.ParseGoAuditFunctionPlugin";
    }

    @Override
    public String getName() {
        return "Go-Audit parser pipeline function";
    }

    @Override
    public String getAuthor() {
        return "Nicholas Neal <nicholas.neal@protonmail.com>";
    }

    @Override
    public URI getURL() {
        return URI.create("https://github.com/YourGitHubUsername/graylog-plugin-function-strlen");
    }

    @Override
    public Version getVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "version", Version.from(0, 0, 1, "unknown"));
    }

    @Override
    public String getDescription() {
        return "Pipeline function that parses a go-audit message, and returns back a JSON string.";
    }

    @Override
    public Version getRequiredVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "graylog.version", Version.from(2, 1, 1));
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }
}
