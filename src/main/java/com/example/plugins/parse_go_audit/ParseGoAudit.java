package com.example.plugins.parse_go_audit;

import org.json.*;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.*;

public class ParseGoAudit {
    // main function to parse message received from go-audit
    public static String parse(String json) {
        
        // parse json string 
        JSONObject parsed = new JSONObject(json);

        // we will return result
        JSONObject result = new JSONObject();

        // add to "data"
        result.put("sequence",parsed.get("sequence"));
        result.put("unknown", new JSONArray());

        // pull uid_map and messages from parsed JSON, or return empty object/array
        JSONObject uid_map = parsed.optJSONObject("uid_map", new JSONObject());
        JSONArray messages = parsed.optJSONArray("messages", new JSONArray());

        // iterate thru messages, directing them to the correct parser
        for (int i = 0; i < messages.length(); i++) {
            Integer type = Integer.valueOf(messages.getJSONObject(i).getInt("type"));
            String data = messages.getJSONObject(i).getString("data");

            if (type.equals(AuditdConstants.TYPES.get("config_change")) || type.equals(AuditdConstants.TYPES.get("syscall"))) {
            //if (type == 1305 || type == 1300) {
                parse_syscall(data, result, uid_map);
            } else if (type.equals(AuditdConstants.TYPES.get("execve"))) {
            //} else if (type == 1309) {
                parse_execve(data, result);
            } else if (type.equals(AuditdConstants.TYPES.get("path"))) {
            //} else if (type == 1302) {
                parse_path(data, result, uid_map);
            } else if (type.equals(AuditdConstants.TYPES.get("cwd"))) {
            //} else if (type == 1307) {
                parse_cwd(data, result);
            } else if (type.equals(AuditdConstants.TYPES.get("sockaddr"))) {
            //} else if (type == 1306) {
                parse_sockaddr(data, result);
            } else if (type.equals(AuditdConstants.TYPES.get("proctitle"))) {
            //} else if (type == 1327) {
                parse_proctitle(data, result);
            } else {
                result.getJSONArray("unknown").put(data);
            }
                
        }

        // build human readable message
        build_summary(result);

        // return json string
        return result.toString();

    }

    private static void parse_syscall(String data, JSONObject result, JSONObject uid_map) {
        // parse data into hashmap
        String[] data_items = data.split(" ");
        Map<String, String> syscall_map = split_fields(data_items);

        // parse arch info into seperate hashmap
        Map<String, Object> arch_map = map_arch(syscall_map);

        // parse uid info into seperate hashmaps
        Map<String, String> id_map = map_uid("uid", syscall_map, uid_map);
        Map<String, String> auid_map = map_uid("auid", syscall_map, uid_map);
        Map<String, String> euid_map = map_uid("euid", syscall_map, uid_map);
        Map<String, String> fsuid_map = map_uid("fsuid", syscall_map, uid_map);
        Map<String, String> suid_map = map_uid("suid", syscall_map, uid_map);

        // remap some values
        syscall_map.put("id", syscall_map.remove("syscall"));
        syscall_map.put("session_id", syscall_map.remove("ses"));

        // if syscall function name defined in auditd constants, add to data.
        if (arch_map != null && 
            AuditdConstants.SYSCALLS.containsKey(arch_map.get("name")) &&
            AuditdConstants.SYSCALLS.get(arch_map.get("name")).containsKey(syscall_map.get("id"))) {
                syscall_map.put("name", AuditdConstants.SYSCALLS.get(arch_map.get("name")).get(syscall_map.get("id")));
            }
        
        // convert some values
        syscall_map.put("key", convert_value(syscall_map.get("key"), true));
        syscall_map.put("command", convert_value(syscall_map.remove("comm"), true));
        syscall_map.put("executable", convert_value(syscall_map.remove("exe"), true));

        // convert to JSONObject and add to root result
        result.put("syscall", new JSONObject(syscall_map));
        if (arch_map != null) result.getJSONObject("syscall").put("arch", new JSONObject(arch_map));
        if (id_map != null) result.getJSONObject("syscall").put("uid", new JSONObject(id_map));
        if (auid_map != null) result.getJSONObject("syscall").put("auid", new JSONObject(auid_map));
        if (euid_map != null) result.getJSONObject("syscall").put("euid", new JSONObject(euid_map));
        if (fsuid_map != null) result.getJSONObject("syscall").put("fsuid", new JSONObject(fsuid_map));
        if (suid_map != null) result.getJSONObject("syscall").put("suid", new JSONObject(suid_map));

    }

    private static void parse_execve(String data, JSONObject result) {
        // parse data into hashmap
        String[] data_items = data.split(" ");
        Map<String, String> execve_map = split_fields(data_items); 

        // if no argc, return map
        if (!execve_map.containsKey("argc")) {
            result.put("execve", new JSONObject(execve_map));
            return;
        }

        // collect argc
        int argc = Integer.valueOf(execve_map.remove("argc"));
        
        // prepare to build command string
        StringBuilder command = new StringBuilder();

        // iterate thru args to build command string
        for (int i = 0; i < argc; i++) {
            //build arg key, and smash subargs to single string
           String find_arg = "a" + i;           
           smash_args(find_arg, execve_map);
           
           // check if arg key in map
           if (!execve_map.containsKey(find_arg)) continue;

           // append arg to command string
           command.append((convert_value(execve_map.remove(find_arg), true)) + " ");
        }

        // compile execve command string and add object to root result.
        execve_map.put("command",command.toString().trim());
        result.put("execve", new JSONObject(execve_map));

    }

    private static void parse_path(String data, JSONObject result, JSONObject uid_map) {
        // parse data into hashmap
        String[] data_items = data.split(" ");
        Map<String, String> path_map = split_fields(data_items);

        // parse ouid info
        Map<String, String> ouid_map = map_uid("ouid", path_map, uid_map);

        // cleanup name and item
        path_map.put("name", convert_value(path_map.get("name"), true));
        path_map.remove("item");

        // create paths array if not created
        if (!result.has("paths")) result.put("paths", new JSONArray());

        // create path Object
        JSONObject path = new JSONObject(path_map);
        if (ouid_map != null) path.put("ouid", new JSONObject(ouid_map));

        // add object to paths array on root result
        result.getJSONArray("paths").put(path);

    }

    private static void parse_cwd(String data, JSONObject result) {
        String[] kv = data.split("=");
        if (kv[0].equals("cwd")) {
            result.put("cwd", convert_value(kv[1], true));
        } else {
            result.put("cwd", "ERROR");
        }
    }

    private static void parse_sockaddr(String data, JSONObject result) {
        String[] kv = data.split("=");
        if (kv[0].equals("saddr")) {
            result.put("sockaddr", new JSONObject(parse_addr(kv[1]))); 
        } else {
            result.put("sockaddr", "ERROR");
        }

    }

    private static void parse_proctitle(String data, JSONObject result) {
        String[] kv = data.split("=");
        if (kv[0].equals("proctitle")) {
            result.put("proctitle", convert_value(kv[1], true)); 
        } else {
            result.put("proctitle", "UNKNOWN");
        }
    }

    private static Map<String, String> parse_addr(String addr) {
        Map<String, String> addr_map = new HashMap<>();

        if (addr.length() < 2) {
            addr_map.put("unknown", addr);
            return addr_map;
        }

        int family = calculate_family(addr);

        if (!AuditdConstants.ADDRESS_FAMILIES.containsKey(family)) {
            addr_map.put("unknown", addr);
            return addr_map;
        }

        addr_map.put("family", AuditdConstants.ADDRESS_FAMILIES.get(family));

        if (family == 1) { // local
            parse_addr_local(addr, addr_map);
        } else if (family == 2) { // inet
            parse_addr_inet(addr, addr_map);
        } else if (family == 10) { // inet6
            parse_addr_inet6(addr, addr_map);
        } else {
            addr_map.put("unknown", addr.substring(4));
        }

        return addr_map;
    }

    private static int calculate_family(String addr) {
        int firstByte = Integer.parseInt(addr.substring(0, 2), 16);
        int secondByte = Integer.parseInt(addr.substring(2, 4), 16);

        return firstByte + (256 * secondByte);
    }

    private static void parse_addr_local(String addr, Map<String, String> details) {
        if (addr.length() < 5) {
            details.put("unknown", addr.substring(2));
            return;
        }

        int pos = addr.indexOf("00", 4) - 4;
        if (pos < 0) {
            pos = addr.length() - 4;
        }

        details.put("path", convert_value(addr.substring(4, pos + 1), true));

        if (addr.length() > pos + 5) {
            details.put("unknown", addr.substring(pos + 4));
        }
    }

    private static void parse_addr_inet(String addr, Map<String, String> details) {
        if (addr.length() < 16) {
            details.put("unknown", addr.substring(2));
            return;
        }

        int port = Integer.parseInt(addr.substring(4, 6), 16) * 256
                + Integer.parseInt(addr.substring(6, 8), 16);
        details.put("port", String.valueOf(port));

        StringBuilder ip = new StringBuilder();
        for (int i = 8; i < 16; i += 2) {
            ip.append(Integer.parseInt(addr.substring(i, i + 2), 16));
            if (i < 14) {
                ip.append(".");
            }
        }
        details.put("ip", ip.toString());

        if (addr.length() > 16) {
            details.put("unknown", addr.substring(16));
        }
    }

    private static void parse_addr_inet6(String addr, Map<String, String> details) {
        if (addr.length() < 56) {
            details.put("unknown", addr.substring(2));
            return;
        }

        int port = Integer.parseInt(addr.substring(4, 6), 16) * 256
                + Integer.parseInt(addr.substring(6, 8), 16);
        details.put("port", String.valueOf(port));

        details.put("flow_info", addr.substring(8, 16));

        StringBuilder ip = new StringBuilder();
        for (int i = 16; i < 48; i += 4) {
            ip.append(addr.substring(i, i + 4).toLowerCase());
            if (i < 44) {
                ip.append(":");
            }
        }
        details.put("ip", ip.toString());

        details.put("scope_id", addr.substring(48, 56));

        if (addr.length() > 56) {
            details.put("unknown", addr.substring(56));
        }
    }

    private static void smash_args(String arg, Map<String, String> data) {
        // compile subarg len key and check if exists
        String argLenKey = arg + "_len";
        if (data.containsKey(argLenKey)) {
            // extract subarg len value and prepare to compile arg to string
            int argLen = Integer.parseInt(data.remove(argLenKey));
            StringBuilder val = new StringBuilder();

            // iterate thru subargs and append to arg string
            for (int i = 0; i < argLen; i++) {
                String subArg = arg + "[" + i + "]";
                if (!data.containsKey(subArg)) {
                    break;
                }
                val.append(data.remove(subArg));
            }

            // add compiled arg to root data map 
            data.put(arg, val.toString());
        }
    }

    private static Map<String, Object> map_arch(Map<String, String> data) {
        if (!data.containsKey("arch")) return null;


        //int tArch = Integer.parseInt(data.get("arch"), 16);
        long tArch = Long.parseLong(data.get("arch"), 16);
        data.remove("arch");

        data.put("arch", "");
        Map<String, Object> arch = new HashMap<>();
        arch.put("bits", null);
        arch.put("endianness", null);
        arch.put("name", null);

        if ((tArch & 0x80000000) == 0) {
            arch.put("bits", 32);
        } else {
            tArch ^= 0x80000000;
            arch.put("bits", 64);
        }

        if ((tArch & 0x40000000) == 0) {
            arch.put("endianness", "big");
        } else {
            tArch ^= 0x40000000;
            arch.put("endianness", "little");
        }

        if ((tArch & 0x20000000) != 0) {
            tArch ^= 0x20000000;
        }

        int finalArch = (int) tArch;
        if (AuditdConstants.MACHINES.containsKey(finalArch)) {
            arch.put("name", AuditdConstants.MACHINES.get(finalArch));
        } else {
            arch.put("name","Unrecognized " + finalArch + " architecture");
        }

        return arch;
    }

    private static Map<String, String> map_uid(String find_uid, Map<String, String> data, JSONObject uid_map) {
        // if uid type not in data, return null
        if (!data.containsKey(find_uid)) return null;

        String uid = data.get(find_uid);

        // overflow uint32 is null
        //if (uid == "4294967295") return null;

        // create map with uid info, and return
        Map<String, String> result = new HashMap<>();
        result.put("name", uid_map.optString(uid, "UNKNOWN_USER"));
        result.put("id", uid);

        return result;
    }

    private static Map<String, String> split_fields(String[] fields) {
        // create new hashmap
        Map<String, String> result = new HashMap<>();
        
        // iterate thru fileds and put kv pairs in to hashmap
        for (int i = 0; i < fields.length; i++) {
            String[] kv = fields[i].split("=");
            result.put(kv[0], kv[1]);
        }

        // return hashmap
        return result;

    }

    private static String convert_value(String str, boolean parseHex) {
        if (str == null) {
            return "";
        } else if (str.startsWith("\"")) {
            return str.substring(1, str.length() - 1);
        //} else if (parseHex && !Pattern.compile("\\p{XDigit}+").matcher(str).find()) {
        } else if (parseHex && Pattern.matches("[0-9A-Fa-f]+",str)) {
            // Assuming "str" represents hexadecimal string
            byte[] bytes = hexStringToByteArray(str);
            String result = new String(bytes).trim();
            // Remove non-printable characters
            return result.replaceAll("[^\\p{Print}]", " ");
        } else if (str.equals("(null)")) {
            return "";
        } else {
            return str;
        }
    }

    // Convert hexadecimal string to byte array
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static JSONObject find_path_type(JSONArray paths, String type) {
        for (int i = 0; i < paths.length(); i++) {
            JSONObject path = paths.getJSONObject(i);
            if (path.get("nametype").equals(type)) {
                return path;
            }
        }

        return null;
    }

    private static String get_path_name(JSONObject path) {
        if (path != null && path.has("name")) {
            return path.getString("name");
        } 

        return null;
    }

    private static void build_summary(JSONObject result) {
        StringBuilder summary = new StringBuilder();

        //command.append((convert_value(execve_map.remove(find_arg), true)) + " ");

        // check if syscall is logged
        if (result.has("syscall")) {
            // if auid exists and is not equal to uid, output auid user's name
            if (
                result.getJSONObject("syscall").has("auid") && 
                result.getJSONObject("syscall").has("uid") &&
                !(result.getJSONObject("syscall").getJSONObject("auid").get("id").equals(result.getJSONObject("syscall").getJSONObject("uid").get("id")))
            ) {
                summary.append(result.getJSONObject("syscall").getJSONObject("auid").get("name"));
                summary.append(" as ");
                //summary += (result.get("syscall").get("auid").get("name") + " as ");
            }

            // who did it?
            if (result.getJSONObject("syscall").has("uid")) {
                summary.append(result.getJSONObject("syscall").getJSONObject("uid").get("name"));
                summary.append(" ");
                //summary += (result.get("syscall").get("uid").get("name") + " ");
            }

            // succeeded or failed?
            if (result.getJSONObject("syscall").has("success")) {
                if (result.getJSONObject("syscall").get("success").equals("yes")) {
                    summary.append("succeeded to ");
                    //summary += "succeeded to ";
                } else {
                    summary.append("failed to ");
                    //summary += "failed to ";
                }
            }

            // to do what?
            if (result.getJSONObject("syscall").has("name")) {
                summary.append(result.getJSONObject("syscall").get("name"));
                summary.append(" ");
                //summary += (result.get("syscall").get("name") + " ");
            } else {
                // will output "[arch] syscall(syscall number)"
                // [386] syscall(42)
                summary.append("[" + result.getJSONObject("syscall").getJSONObject("arch").get("name") + "] ");
                summary.append("syscall(" + result.getJSONObject("syscall").get("id") + ") ");
                //summary += ("[" + result.get("syscall").get("arch").get("name") + "] syscall(" + result.get("syscall").get("id") + ") ");
            } 

            boolean includeCmd = false;
            String path = null;

            // if execve was called, get command
            if (result.has("execve") && result.getJSONObject("execve").has("command")) {
                path = result.getJSONObject("execve").getString("command");
                summary.append(path.split(" ",2)[0]);
                summary.append(" ");
                //summary += (execve[0] + " ");
            // if cretain syscall functions were called, handle accordingly
            } else if (result.getJSONObject("syscall").has("name")) {
                String syscall_name = result.getJSONObject("syscall").getString("name");
                // capture rename params
                if (syscall_name.equals("rename")) {
                    summary.append(get_path_name(find_path_type(result.getJSONArray("paths"), "DELETE")));
                    summary.append(" to ");
                    summary.append(get_path_name(find_path_type(result.getJSONArray("paths"), "CREATE")));
                    summary.append(" ");
                // capture network info
                } else if (syscall_name.equals("bind") || syscall_name.equals("connect") || syscall_name.equals("sendto")) {
                    summary.append("to ");
                    includeCmd = true;
                    if (result.has("sockaddr")) {
                        // if IP address & port
                        if (result.getJSONObject("sockaddr").has("ip") && result.getJSONObject("sockaddr").has("port")) {
                            summary.append(result.getJSONObject("sockaddr").get("ip") + ":" + result.getJSONObject("sockaddr").get("port"));
                            summary.append(" ");
                        // if socket file
                        } else if (result.getJSONObject("sockaddr").has("path")) {
                            summary.append(result.getJSONObject("sockaddr").get("path"));
                            summary.append(" ");
                        } else {
                            summary.append("unknown address ");
                        }
                    } else {
                        summary.append("unknown address ");
                    }
                // everything else
                } else {
                    JSONObject created;
                    JSONObject normal;
                    if (result.has("paths") && (created = find_path_type(result.getJSONArray("paths"), "CREATE")) != null) {
                        path = get_path_name(created);
                    } else if (result.has("paths") && (normal = find_path_type(result.getJSONArray("paths"), "CREATE")) != null) {
                        path = get_path_name(normal);
                    } else {
                        path = "unknown path";
                    }

                    summary.append(path);
                    summary.append(" ");
                }
            }

            if (result.getJSONObject("syscall").has("executable") && !(result.getJSONObject("syscall").get("executable").equals(path))) {
                summary.append("via ");
                summary.append(result.getJSONObject("syscall").get("executable"));
                summary.append(" ");
            }

            if (includeCmd && result.getJSONObject("syscall").has("command")) {
                summary.append("as ");
                summary.append(result.getJSONObject("syscall").get("command"));
                summary.append(" ");
            }
        
        } else {
            summary.append("none");
        }

        result.put("summary", summary.toString());

    }
}
