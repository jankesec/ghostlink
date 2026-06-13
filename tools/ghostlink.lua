-- Ghostlink Protocol Dissector for Wireshark
-- Install: copy to ~/.local/lib/wireshark/plugins/ or Wireshark plugins dir
-- Usage: Analyze > Decode As > select port > ghostlink

local ghostlink = Proto("ghostlink", "Ghostlink C2 Protocol")

local f_version = ProtoField.uint8("ghostlink.version", "Version", base.HEX)
local f_type = ProtoField.uint8("ghostlink.type", "Type", base.HEX)
local f_stream_id = ProtoField.uint32("ghostlink.stream_id", "Stream ID", base.DEC)
local f_payload_len = ProtoField.uint16("ghostlink.payload_len", "Payload Length", base.DEC)
local f_payload = ProtoField.bytes("ghostlink.payload", "Payload")

ghostlink.fields = {f_version, f_type, f_stream_id, f_payload_len, f_payload}

local msg_types = {
    [0x01] = "ShellStdin",
    [0x02] = "ShellStdout",
    [0x03] = "ShellStderr",
    [0x04] = "CmdReq",
    [0x05] = "CmdRes",
    [0x06] = "FilePut",
    [0x07] = "FileGetReq",
    [0x08] = "FileGetChunk",
    [0x10] = "FwdConnect",
    [0x11] = "FwdData",
    [0x12] = "FwdClose",
    [0x13] = "SocksConnect",
    [0x14] = "SocksData",
    [0x15] = "SocksClose",
    [0x20] = "Ping",
    [0x21] = "Pong",
    [0x30] = "Reconnect",
    [0x31] = "SessionID",
    [0x40] = "ModuleList",
    [0x41] = "ModuleExec",
    [0x42] = "ModuleResult",
    [0xFF] = "Error"
}

function ghostlink.dissector(buffer, pinfo, tree)
    if buffer:len() < 8 then return end

    pinfo.cols.protocol = "GHOSTLINK"

    local subtree = tree:add(ghostlink, buffer(), "Ghostlink Protocol")

    local version = buffer(0, 1):uint()
    local msg_type = buffer(1, 1):uint()
    local stream_id = buffer(2, 4):uint()
    local payload_len = buffer(6, 2):uint()

    subtree:add(f_version, buffer(0, 1))
    local type_node = subtree:add(f_type, buffer(1, 1))
    subtree:add(f_stream_id, buffer(2, 4))
    subtree:add(f_payload_len, buffer(6, 2))

    local type_name = msg_types[msg_type] or "Unknown"
    type_node:append_text(" (" .. type_name .. ")")

    pinfo.cols.info = string.format("v%d %s stream=%d len=%d",
        version, type_name, stream_id, payload_len)

    if payload_len > 0 and buffer:len() >= 8 + payload_len then
        subtree:add(f_payload, buffer(8, payload_len))

        if msg_type == 0x04 or msg_type == 0x05 then
            subtree:add(buffer(8, payload_len), "Data: " .. buffer(8, payload_len):string())
        end
    end
end

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(16353, ghostlink)
