# graylog-parse-goaudit

This is a graylog pipeline function based on Marcin Wielgoszewski's [logstash-filter-goaudit](https://github.com/mwielgoszewski/logstash-filter-goaudit).

## Disclaimer
This is a personal project that has had limited testing on production workloads. If someone were to use this in a production environment, it should be known that they are doing so at a risk. 

## Pre-Requisites
You should already have an instance of graylog-server 5.2 or higher (*Note: Earlier versions have not been tested*) confiured and running, as well as go-audit input forwarding to graylog-server via syslog.

You can learn more about graylog-server [here](https://go2docs.graylog.org/current/what_is_graylog/what_is_graylog.htm).

You can learn more about go-audit [here](https://slack.engineering/syscall-auditing-at-scale/).

## Installation
### Compile the plugin jar
> [!NOTE]
> This documentation assumes that you have a maven build environment already configured. 

To compile the plugin, run the following commands:
```bash
# clone project into workspace 
git clone (this repo)
cd graylog-parse-goaudit

# build plugin
mvn install
```

If the build was successful, you'll find the plugin jar at `./target/graylog-plugin-function-parse-go-audit-1.0.jar`.

### Load the plugin into graylog-server
> [!NOTE]
> This documentation assumes your graylog-server is setup and configured on Ubuntu 22.04. Please adjust the documentation according to your environment. 

Once you have copied the `graylog-plugin-function-parse-go-audit-1.0.jar` file to your graylog server, you will want to move it to the `/usr/share/graylog-server/plugin/` directory.

Once that has been completed, you will need to restart the graylog-server to load in the newly installed plugin:
```bash
systemctl restart graylog-server.service
```

### Configure graylog-server to parse go-audit messages
Before parsing go-audit messages, you will need to create a pipeline to identify which messages are go-audit logs, and parse/flatten them accordingly.

#### Create Pipeline Rule
1. Go to System > Pipelines > Manage rules
2. click **Create Rule** 
3. click **Use Source Code Editor**
4. Add the following to the **Rule Source** field:
    ```
    rule "Parse go-audit message"
    when (has_field("application_name") && to_string($message."application_name") == "go-audit")
    then
      let message_json = flatten_json(parse_go_audit(to_string($message.message)),"flatten");
      set_fields(to_map(parse_json(to_string(message_json))));
    end
    ```
5. Click **Create Rule**

#### Create Pipeline
1. Go to System > Pipelines > Manage pipelines
2. Click **Add new pipeline**
3. Set the Title field to "go-audit"
4. Click **Create pipeline**
5. Under Pipeline connections, click **Edit connections**
    - Select the stream your go-audit messages will come in on (select **Default Stream** if there are no other options)
    - Click on **Update Connections**
6. Under Stage 0, click on **Edit**
    - Under **Stage Rules**, select the "Parse go-audit message" rule
    - Click **Update Stage**

If everything has been configured correctly, your go-audit messages should now be flattened and searchable.

