#include "common.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

#define SERVICE_NAME "protection_mgr"

typedef struct {
    bool active;
    uint32_t switchover_count;
    // Track which connections are switched vs normal
    // Key: connection name, Values: original line port, current line port
    char switched_conns[MAX_CONNS][MAX_CONN_NAME_CHARACTER];
    uint8_t original_line_ports[MAX_CONNS];
    uint8_t current_line_ports[MAX_CONNS];
    uint8_t switched_count;
} protection_state_t;

static protection_state_t protection = {0};
static int client_socket = 0;

void initialize_protection()
{
    memset(&protection, 0, sizeof(protection));
    LOG(LOG_INFO, "Protection Manager initialized");
}

bool get_port_info(uint8_t port_id, port_t *out)
{
    udp_message_t req = {0};
    req.msg_type = MSG_GET_PORT_INFO;
    req.status = STATUS_REQUEST;

    udp_port_cmd_request_t *payload = (udp_port_cmd_request_t *)req.payload;
    payload->port_id = port_id;

    udp_message_t resp = {0};
    if (!send_udp_message_and_receive(client_socket, &req, &resp, PORT_MANAGER_UDP)) {
        LOG(LOG_ERROR, "Failed to get port info for port-%d", port_id);
        return false;
    }

    if (resp.status != STATUS_SUCCESS) {
        LOG(LOG_ERROR, "Port-%d query failed", port_id);
        return false;
    }

    memcpy(out, resp.payload, sizeof(*out));
    return true;
}

bool get_connections(udp_get_connections_reply_t *out)
{
    udp_message_t req = {0};
    req.msg_type = MSG_GET_CONNECTIONS;
    req.status = STATUS_REQUEST;

    udp_message_t resp = {0};
    if (!send_udp_message_and_receive(client_socket, &req, &resp, CONN_MANAGER_UDP)) {
        LOG(LOG_ERROR, "Failed to get connections");
        return false;
    }

    if (resp.status != STATUS_SUCCESS) {
        LOG(LOG_ERROR, "Get connections query failed");
        return false;
    }

    memcpy(out, resp.payload, sizeof(*out));
    return true;
}

bool is_connection_switched(const char *conn_name)
{
    for (uint8_t i = 0; i < protection.switched_count; i++) {
        if (strncmp(protection.switched_conns[i], conn_name, MAX_CONN_NAME_CHARACTER) == 0) {
            return true;
        }
    }
    return false;
}

uint8_t get_switched_line_port(const char *conn_name)
{
    for (uint8_t i = 0; i < protection.switched_count; i++) {
        if (strncmp(protection.switched_conns[i], conn_name, MAX_CONN_NAME_CHARACTER) == 0) {
            return protection.current_line_ports[i];
        }
    }
    return 0;
}

uint8_t get_original_line_port(const char *conn_name)
{
    for (uint8_t i = 0; i < protection.switched_count; i++) {
        if (strncmp(protection.switched_conns[i], conn_name, MAX_CONN_NAME_CHARACTER) == 0) {
            return protection.original_line_ports[i];
        }
    }
    return 0;
}

bool switch_connection_line(const char *conn_name, uint8_t new_line_port)
{
    udp_message_t req = {0};
    req.msg_type = MSG_SWITCH_CONN_LINE;
    req.status = STATUS_REQUEST;

    udp_switch_conn_line_request_t *payload = (udp_switch_conn_line_request_t *)req.payload;
    strncpy(payload->name, conn_name, MAX_CONN_NAME_CHARACTER - 1);
    payload->new_line_port = new_line_port;

    udp_message_t resp = {0};
    if (!send_udp_message_and_receive(client_socket, &req, &resp, CONN_MANAGER_UDP)) {
        LOG(LOG_ERROR, "Failed to switch connection %s line port to %d", conn_name, new_line_port);
        return false;
    }

    if (resp.status != STATUS_SUCCESS) {
        LOG(LOG_ERROR, "Connection manager failed to switch %s", conn_name);
        return false;
    }

    return true;
}

void add_switched_connection(const char *conn_name, uint8_t original_line_port, uint8_t new_line_port)
{
    if (protection.switched_count >= MAX_CONNS) {
        LOG(LOG_ERROR, "Cannot track more switched connections");
        return;
    }

    if (!switch_connection_line(conn_name, new_line_port)) {
        LOG(LOG_ERROR, "Failed to switch connection in manager");
        return;
    }

    strncpy(protection.switched_conns[protection.switched_count], conn_name, MAX_CONN_NAME_CHARACTER - 1);
    protection.original_line_ports[protection.switched_count] = original_line_port;
    protection.current_line_ports[protection.switched_count] = new_line_port;
    protection.switched_count++;
}

void remove_switched_connection(const char *conn_name)
{
    for (uint8_t i = 0; i < protection.switched_count; i++) {
        if (strncmp(protection.switched_conns[i], conn_name, MAX_CONN_NAME_CHARACTER) == 0) {
            // Revert the connection back to original line port
            uint8_t original_port = protection.original_line_ports[i];
            if (!switch_connection_line(conn_name, original_port)) {
                LOG(LOG_ERROR, "Failed to revert connection %s", conn_name);
            }

            // Shift remaining entries
            for (uint8_t j = i; j < protection.switched_count - 1; j++) {
                strncpy(protection.switched_conns[j], protection.switched_conns[j + 1], MAX_CONN_NAME_CHARACTER);
                protection.original_line_ports[j] = protection.original_line_ports[j + 1];
                protection.current_line_ports[j] = protection.current_line_ports[j + 1];
            }
            protection.switched_count--;
            return;
        }
    }
}

void handle_set_protection_group(udp_message_t *resp)
{
    if (protection.active) {
        set_error_msg(resp, "protection group already active");
        return;
    }

    // Check that ports 1 and 2 exist and are admin-enabled line ports
    port_t port1, port2;
    if (!get_port_info(1, &port1) || !get_port_info(2, &port2)) {
        set_error_msg(resp, "failed to query port state");
        return;
    }

    if (port1.type != LINE_PORT || port2.type != LINE_PORT) {
        set_error_msg(resp, "ports 1 and 2 must be line ports");
        return;
    }

    if (!port1.admin_enabled || !port2.admin_enabled) {
        set_error_msg(resp, "both ports must be admin-enabled");
        return;
    }

    protection.active = true;
    protection.switchover_count = 0;
    memset(protection.switched_conns, 0, sizeof(protection.switched_conns));
    memset(protection.original_line_ports, 0, sizeof(protection.original_line_ports));
    memset(protection.current_line_ports, 0, sizeof(protection.current_line_ports));
    protection.switched_count = 0;

    resp->status = STATUS_SUCCESS;
    LOG(LOG_INFO, "Protection group activated: port-1 ↔ port-2");
}

void handle_delete_protection_group(udp_message_t *resp)
{
    if (!protection.active) {
        set_error_msg(resp, "no active protection group");
        return;
    }

    // Revert all switched connections back to their original ports
    while (protection.switched_count > 0) {
        const char *conn_name = protection.switched_conns[0];
        uint8_t original_port = protection.original_line_ports[0];
        
        LOG(LOG_INFO, "Revertive switch: %s reverts to port-%d", conn_name, original_port);
        remove_switched_connection(conn_name);
    }

    protection.active = false;
    resp->status = STATUS_SUCCESS;
    LOG(LOG_INFO, "Protection group deactivated");
}

void handle_show_protection_group(udp_message_t *resp)
{
    udp_protection_group_reply_t *reply = (udp_protection_group_reply_t *)resp->payload;
    memset(reply, 0, sizeof(*reply));

    reply->active = protection.active;
    reply->switchover_count = protection.switchover_count;

    if (!protection.active) {
        LOG(LOG_INFO, "Protection Group: INACTIVE");
        resp->status = STATUS_SUCCESS;
        return;
    }

    LOG(LOG_INFO, "Protection Group: ACTIVE");
    LOG(LOG_INFO, "Members: port-1 ↔ port-2");
    LOG(LOG_INFO, "Switchovers: %u", protection.switchover_count);

    udp_get_connections_reply_t conns = {0};
    if (!get_connections(&conns)) {
        LOG(LOG_ERROR, "Failed to get connections for status display");
        resp->status = STATUS_FAILURE;
        return;
    }

    for (uint8_t i = 0; i < conns.conn_count && i < MAX_CONNS; i++) {
        conn_t *conn = &conns.all_connections[i];
        uint8_t original_line = get_original_line_port(conn->conn_name);
        if (original_line == 0) {
            original_line = conn->line_port;  // If not tracked as switched, original is current
        }

        // Add to reply
        reply->protected_conns[i] = *conn;
        reply->current_line_ports[i] = conn->line_port; // Current line port is what's in the connection

        const char *state = is_connection_switched(conn->conn_name) ? "switched" : "normal";
        LOG(LOG_INFO, "Connection %s: original=port-%d current=port-%d state=%s",
            conn->conn_name, original_line, conn->line_port, state);
    }

    reply->conn_count = conns.conn_count;
    resp->status = STATUS_SUCCESS;
}

void check_port_faults()
{
    if (!protection.active) {
        return;
    }

    port_t port1, port2;
    if (!get_port_info(1, &port1) || !get_port_info(2, &port2)) {
        return;
    }

    // Check if port 1 has faulted
    if (port1.fault_active && port1.operational_state == PORT_DOWN) {
        LOG(LOG_INFO, "Port-1 fault detected, switching connections to port-2");

        // Get all connections and switch those on port 1
        udp_get_connections_reply_t conns = {0};
        if (get_connections(&conns)) {
            for (uint8_t i = 0; i < conns.conn_count; i++) {
                if (conns.all_connections[i].line_port == 1 && !is_connection_switched(conns.all_connections[i].conn_name)) {
                    add_switched_connection(conns.all_connections[i].conn_name, 1, 2);
                    protection.switchover_count++;
                    LOG(LOG_INFO, "Protection switchover: %s moved from port-1 → port-2",
                        conns.all_connections[i].conn_name);
                }
            }
        }
    }
    // Check if port 2 has faulted
    else if (port2.fault_active && port2.operational_state == PORT_DOWN) {
        LOG(LOG_INFO, "Port-2 fault detected, switching connections to port-1");

        // Get all connections and switch those on port 2
        udp_get_connections_reply_t conns = {0};
        if (get_connections(&conns)) {
            for (uint8_t i = 0; i < conns.conn_count; i++) {
                if (conns.all_connections[i].line_port == 2 && !is_connection_switched(conns.all_connections[i].conn_name)) {
                    add_switched_connection(conns.all_connections[i].conn_name, 2, 1);
                    protection.switchover_count++;
                    LOG(LOG_INFO, "Protection switchover: %s moved from port-2 → port-1",
                        conns.all_connections[i].conn_name);
                }
            }
        }
    }
    // Check if faults have cleared for revertive switching
    else if (!port1.fault_active && port1.operational_state == PORT_UP) {
        // Revert connections back to port 1
        udp_get_connections_reply_t conns = {0};
        if (get_connections(&conns)) {
            for (uint8_t i = 0; i < conns.conn_count; i++) {
                const char *conn_name = conns.all_connections[i].conn_name;
                if (get_original_line_port(conn_name) == 1 && is_connection_switched(conn_name)) {
                    uint8_t current = get_switched_line_port(conn_name);
                    LOG(LOG_INFO, "Revertive switch: %s moved from port-%u → port-1",
                        conn_name, current);
                    remove_switched_connection(conn_name);
                }
            }
        }
    }
    else if (!port2.fault_active && port2.operational_state == PORT_UP) {
        // Revert connections back to port 2
        udp_get_connections_reply_t conns = {0};
        if (get_connections(&conns)) {
            for (uint8_t i = 0; i < conns.conn_count; i++) {
                const char *conn_name = conns.all_connections[i].conn_name;
                if (get_original_line_port(conn_name) == 2 && is_connection_switched(conn_name)) {
                    uint8_t current = get_switched_line_port(conn_name);
                    LOG(LOG_INFO, "Revertive switch: %s moved from port-%u → port-2",
                        conn_name, current);
                    remove_switched_connection(conn_name);
                }
            }
        }
    }
}

bool dispatch(const udp_message_t *req, udp_message_t *resp)
{
    bool send_reply = true;
    resp->msg_type = req->msg_type;
    resp->status = STATUS_FAILURE;

    switch ((msg_type_t)req->msg_type) {
    case MSG_SET_PROTECTION_GROUP:
        handle_set_protection_group(resp);
        break;

    case MSG_DELETE_PROTECTION_GROUP:
        handle_delete_protection_group(resp);
        break;

    case MSG_GET_PROTECTION_GROUP:
        handle_show_protection_group(resp);
        break;

    default:
        LOG(LOG_WARN, "Unknown msg_type: %d", req->msg_type);
        send_reply = false;
        break;
    }

    return send_reply;
}

int main()
{
    log_init(SERVICE_NAME);
    initialize_protection();

    int server_socket = create_udp_server(PROTECTION_MGR_UDP);
    if (server_socket < 0) {
        LOG(LOG_ERROR, "Failed to create server socket - exiting");
        return 1;
    }

    client_socket = create_udp_client();
    if (client_socket < 0) {
        LOG(LOG_ERROR, "Failed to create client socket - exiting");
        return 1;
    }

    struct timeval rx_timeout = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, &rx_timeout, sizeof(rx_timeout));

    time_t last_check = time(NULL);

    while (true) {
        udp_message_t req = {0};
        struct sockaddr_in sender = {0};
        socklen_t sender_len = sizeof(sender);

        ssize_t n = recvfrom(server_socket, &req, sizeof(req), 0,
            (struct sockaddr *)&sender, &sender_len);

        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG(LOG_ERROR, "recvfrom failed");
        } else if (n > 0) {
            udp_message_t resp = {0};
            if (dispatch(&req, &resp) &&
                (sendto(server_socket, &resp, sizeof(resp), 0,
                    (struct sockaddr *)&sender, sender_len) < 0)) {
                LOG(LOG_ERROR, "sendto reply failed");
            }
        }

        // Periodically check for port faults and handle switchovers
        time_t now = time(NULL);
        if (now - last_check >= 1) {
            check_port_faults();
            last_check = now;
        }
    }

    return 0;
}
