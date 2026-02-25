#include "ndef.hpp"
#include <cstring>
#include <esp_log.h>
#include <esp_timer.h>

#define TAG "ndef"

// NFC Forum Type 4 Tag APDU handler, matching the Numo HCE implementation.
// Reference: Numo docs/NDEF_Payer_Side_Spec.md

// -------------------------------------------------------------------------
// Constants (match Numo's NdefConstants)
// -------------------------------------------------------------------------

static const uint8_t SW_OK[]        = {0x90, 0x00};
static const uint8_t SW_NOT_FOUND[] = {0x6A, 0x82};

static const uint8_t NDEF_AID_SELECT[] = {
    0x00, 0xA4, 0x04, 0x00, 0x07,
    0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00
};

static const uint8_t SELECT_FILE_HDR[] = {0x00, 0xA4, 0x00, 0x0C};
static const uint8_t READ_BINARY_HDR[] = {0x00, 0xB0};
static const uint8_t UPDATE_BINARY_HDR[] = {0x00, 0xD6};

static const uint8_t CC_FILE_ID[] = {0xE1, 0x03};
static const uint8_t NDEF_FILE_ID[] = {0xE1, 0x04};

// Capability Container -- matches Numo exactly
static const uint8_t CC_FILE[] = {
    0x00, 0x0F,       // CCLEN = 15
    0x20,             // Mapping version 2.0
    0x00, 0x3B,       // MLe = 59
    0x00, 0x34,       // MLc = 52
    0x04,             // NDEF File Control TLV type
    0x06,             // TLV length
    0xE1, 0x04,       // NDEF file ID
    0x70, 0xFF,       // Max NDEF size = 28671
    0x00,             // Read access: unrestricted
    0x00              // Write access: unrestricted
};
static const size_t CC_FILE_LEN = sizeof(CC_FILE);

// -------------------------------------------------------------------------
// State
// -------------------------------------------------------------------------

static bool s_app_selected = false;

enum SelectedFile { SEL_NONE, SEL_CC, SEL_NDEF };
static SelectedFile s_selected = SEL_NONE;

// Outgoing NDEF file (NLEN + Text record) served on READ BINARY
static uint8_t s_ndef_file[NDEF_MAX_DATA_SIZE];
static size_t s_ndef_file_len = 0;

// Incoming receive buffer for UPDATE BINARY
static uint8_t s_recv_buf[NDEF_MAX_DATA_SIZE];
static int s_expected_nlen = -1;
static int64_t s_last_write_time = 0;

static ndef_message_cb_t s_recv_callback;

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

static void append_sw(uint8_t *buf, size_t *pos, const uint8_t sw[2])
{
    buf[(*pos)++] = sw[0];
    buf[(*pos)++] = sw[1];
}

static bool mem_starts_with(const uint8_t *data, size_t data_len,
                            const uint8_t *prefix, size_t prefix_len)
{
    if (data_len < prefix_len) return false;
    return memcmp(data, prefix, prefix_len) == 0;
}

static bool has_nonzero_data(const uint8_t *buf, int nlen)
{
    int end = nlen + 2;
    if (end > (int)NDEF_MAX_DATA_SIZE) end = (int)NDEF_MAX_DATA_SIZE;
    for (int i = 2; i < end; i++)
        if (buf[i] != 0) return true;
    return false;
}

static void process_complete_message()
{
    int copy_len;
    if (s_expected_nlen > 0 && (s_expected_nlen + 2) <= (int)NDEF_MAX_DATA_SIZE)
        copy_len = s_expected_nlen + 2;
    else
        copy_len = (int)NDEF_MAX_DATA_SIZE;

    ESP_LOGI(TAG, "complete NDEF message received (%d bytes)", copy_len);

    if (s_recv_callback)
        s_recv_callback(s_recv_buf, (size_t)copy_len);
}

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

void ndef_init()
{
    s_app_selected = false;
    s_selected = SEL_NONE;
    s_ndef_file_len = 0;
    ndef_reset_receive();
    s_recv_callback = nullptr;
}

void ndef_reset_receive()
{
    memset(s_recv_buf, 0, sizeof(s_recv_buf));
    s_expected_nlen = -1;
    s_last_write_time = 0;
}

void ndef_set_receive_callback(ndef_message_cb_t cb)
{
    s_recv_callback = cb;
}

bool ndef_set_message(const char *text)
{
    size_t text_len = strlen(text);
    size_t lang_len = 2; // "en"
    size_t payload_len = 1 + lang_len + text_len; // status byte + lang + text

    bool short_record = (payload_len <= 255);
    size_t record_len;
    if (short_record)
        record_len = 1 + 1 + 1 + 1 + payload_len; // header, type_len, payload_len(1), type, payload
    else
        record_len = 1 + 1 + 4 + 1 + payload_len; // header, type_len, payload_len(4), type, payload

    size_t total = 2 + record_len; // NLEN (2 bytes) + record
    if (total > NDEF_MAX_DATA_SIZE) {
        ESP_LOGE(TAG, "NDEF message too large (%d bytes)", (int)total);
        return false;
    }

    uint8_t *p = s_ndef_file;

    // NLEN (big-endian 16-bit length of record, excluding NLEN itself)
    p[0] = (record_len >> 8) & 0xFF;
    p[1] = record_len & 0xFF;
    p += 2;

    // NDEF record header
    if (short_record) {
        *p++ = 0xD1; // MB=1, ME=1, SR=1, TNF=1 (well-known)
        *p++ = 0x01; // type length
        *p++ = (uint8_t)payload_len;
    } else {
        *p++ = 0xC1; // MB=1, ME=1, SR=0, TNF=1 (well-known)
        *p++ = 0x01; // type length
        *p++ = (payload_len >> 24) & 0xFF;
        *p++ = (payload_len >> 16) & 0xFF;
        *p++ = (payload_len >> 8) & 0xFF;
        *p++ = payload_len & 0xFF;
    }
    *p++ = 0x54; // type = 'T' (Text)

    // Payload: status byte + "en" + text
    *p++ = (uint8_t)lang_len;
    *p++ = 'e';
    *p++ = 'n';
    memcpy(p, text, text_len);
    p += text_len;

    s_ndef_file_len = (size_t)(p - s_ndef_file);
    ESP_LOGI(TAG, "NDEF message set: %d bytes (text %d chars)", (int)s_ndef_file_len, (int)text_len);
    return true;
}

void ndef_clear_message()
{
    s_ndef_file_len = 0;
    s_selected = SEL_NONE;
}

bool ndef_handle_apdu(const uint8_t *apdu, size_t apdu_len,
                      uint8_t *response, size_t *response_len)
{
    *response_len = 0;

    if (apdu_len < 4) {
        append_sw(response, response_len, SW_NOT_FOUND);
        return true;
    }

    // SELECT AID
    if (apdu_len >= sizeof(NDEF_AID_SELECT) &&
        mem_starts_with(apdu, apdu_len, NDEF_AID_SELECT, sizeof(NDEF_AID_SELECT))) {
        ESP_LOGI(TAG, "SELECT AID");
        s_app_selected = true;
        append_sw(response, response_len, SW_OK);
        return true;
    }

    // SELECT FILE
    if (mem_starts_with(apdu, apdu_len, SELECT_FILE_HDR, sizeof(SELECT_FILE_HDR))
        && apdu_len >= 7) {
        const uint8_t *file_id = apdu + 5;

        if (memcmp(file_id, CC_FILE_ID, 2) == 0) {
            ESP_LOGI(TAG, "SELECT CC file");
            s_selected = SEL_CC;
            append_sw(response, response_len, SW_OK);
            return true;
        }

        if (memcmp(file_id, NDEF_FILE_ID, 2) == 0) {
            if (s_ndef_file_len > 0) {
                ESP_LOGI(TAG, "SELECT NDEF file (%d bytes)", (int)s_ndef_file_len);
                s_selected = SEL_NDEF;
                ndef_reset_receive();
                append_sw(response, response_len, SW_OK);
            } else {
                ESP_LOGW(TAG, "SELECT NDEF file -- no message loaded");
                append_sw(response, response_len, SW_NOT_FOUND);
            }
            return true;
        }

        ESP_LOGW(TAG, "SELECT unknown file %02X%02X", file_id[0], file_id[1]);
        append_sw(response, response_len, SW_NOT_FOUND);
        return true;
    }

    // READ BINARY
    if (mem_starts_with(apdu, apdu_len, READ_BINARY_HDR, sizeof(READ_BINARY_HDR))
        && apdu_len >= 5) {
        int offset = (apdu[2] << 8) | apdu[3];
        int le = apdu[4];
        if (le == 0) le = 256;

        const uint8_t *file_data = nullptr;
        int file_len = 0;

        if (s_selected == SEL_CC) {
            file_data = CC_FILE;
            file_len = (int)CC_FILE_LEN;
        } else if (s_selected == SEL_NDEF) {
            file_data = s_ndef_file;
            file_len = (int)s_ndef_file_len;
        }

        if (!file_data || offset + le > file_len) {
            ESP_LOGW(TAG, "READ BINARY out of bounds (off=%d le=%d file=%d)",
                     offset, le, file_len);
            append_sw(response, response_len, SW_NOT_FOUND);
            return true;
        }

        memcpy(response, file_data + offset, le);
        *response_len = le;
        append_sw(response, response_len, SW_OK);
        ESP_LOGD(TAG, "READ BINARY off=%d le=%d", offset, le);
        return true;
    }

    // UPDATE BINARY
    if (mem_starts_with(apdu, apdu_len, UPDATE_BINARY_HDR, sizeof(UPDATE_BINARY_HDR))
        && apdu_len >= 5) {

        if (s_selected == SEL_CC) {
            ESP_LOGW(TAG, "UPDATE BINARY to CC file -- forbidden");
            append_sw(response, response_len, SW_NOT_FOUND);
            return true;
        }

        if (s_selected != SEL_NDEF) {
            ESP_LOGW(TAG, "UPDATE BINARY -- no file selected");
            append_sw(response, response_len, SW_NOT_FOUND);
            return true;
        }

        int offset = (apdu[2] << 8) | apdu[3];
        int lc = apdu[4];

        if (apdu_len < (size_t)(5 + lc)) {
            ESP_LOGW(TAG, "UPDATE BINARY truncated");
            append_sw(response, response_len, SW_NOT_FOUND);
            return true;
        }

        if (offset + lc > (int)NDEF_MAX_DATA_SIZE) {
            ESP_LOGW(TAG, "UPDATE BINARY overflow");
            append_sw(response, response_len, SW_NOT_FOUND);
            return true;
        }

        memcpy(s_recv_buf + offset, apdu + 5, lc);
        s_last_write_time = esp_timer_get_time();

        ESP_LOGD(TAG, "UPDATE BINARY off=%d lc=%d", offset, lc);

        // Check for NLEN header at offset 0
        if (offset == 0 && lc >= 2) {
            int new_nlen = (s_recv_buf[0] << 8) | s_recv_buf[1];

            if (new_nlen == 0) {
                s_expected_nlen = 0;
                ESP_LOGD(TAG, "NLEN header: 0 (init)");
            } else {
                s_expected_nlen = new_nlen;
                ESP_LOGI(TAG, "NLEN header: %d", new_nlen);

                // Check if this single write contains the full message
                if (offset + lc >= new_nlen + 2) {
                    append_sw(response, response_len, SW_OK);
                    process_complete_message();
                    return true;
                }

                // Check if body was already written (NLEN=0 then body then final NLEN pattern)
                if (has_nonzero_data(s_recv_buf, new_nlen)) {
                    append_sw(response, response_len, SW_OK);
                    process_complete_message();
                    return true;
                }
            }
        } else if (s_expected_nlen > 0) {
            // Body chunk: check if we've reached the expected length
            if (offset + lc >= s_expected_nlen + 2) {
                append_sw(response, response_len, SW_OK);
                process_complete_message();
                return true;
            }
        }

        append_sw(response, response_len, SW_OK);
        return true;
    }

    ESP_LOGW(TAG, "unknown APDU: CLA=%02X INS=%02X", apdu[0], apdu[1]);
    append_sw(response, response_len, SW_NOT_FOUND);
    return true;
}

// -------------------------------------------------------------------------
// NDEF message parsing
// -------------------------------------------------------------------------

bool ndef_parse_message(const uint8_t *data, size_t len, std::string &text_out)
{
    if (len < 2) return false;

    int nlen = (data[0] << 8) | data[1];
    if (nlen <= 0 || (size_t)(nlen + 2) > len) return false;

    size_t offset = 2;
    if (offset >= len) return false;

    uint8_t header = data[offset];
    if (offset + 1 >= len) return false;
    uint8_t type_length = data[offset + 1];
    if (type_length == 0) return false;

    bool sr = (header & 0x10) != 0; // Short Record flag
    int payload_length;
    size_t type_start;

    if (sr) {
        if (offset + 2 >= len) return false;
        payload_length = data[offset + 2];
        type_start = offset + 3;
    } else {
        if (offset + 5 >= len) return false;
        payload_length = (data[offset + 2] << 24) | (data[offset + 3] << 16) |
                         (data[offset + 4] << 8) | data[offset + 5];
        type_start = offset + 6;
    }

    if (payload_length <= 0) return false;
    if (type_start + type_length > len) return false;

    size_t payload_start = type_start + type_length;
    if (payload_start + payload_length > len + 2) return false; // allow for NLEN

    // Text record: type = 'T' (0x54)
    if (type_length == 1 && data[type_start] == 0x54) {
        if (payload_length < 1) return false;
        uint8_t status = data[payload_start];
        int lang_len = status & 0x3F;
        int text_start_off = (int)payload_start + 1 + lang_len;
        int text_len = payload_length - 1 - lang_len;
        if (text_len <= 0 || text_start_off + text_len > (int)len + 2) return false;
        text_out.assign((const char *)&data[text_start_off], text_len);
        return true;
    }

    // URI record: type = 'U' (0x55)
    if (type_length == 1 && data[type_start] == 0x55) {
        if (payload_length < 1) return false;
        uint8_t id_code = data[payload_start];
        int uri_start = (int)payload_start + 1;
        int uri_len = payload_length - 1;
        if (uri_len <= 0 || uri_start + uri_len > (int)len + 2) return false;

        static const char *uri_prefixes[] = {
            "", "http://www.", "https://www.", "http://", "https://",
            "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.",
            "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://",
            "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:",
            "sip:", "sips:", "tftp:", "btspp://", "btl2cap://",
            "btgoep://", "tcpobex://", "irdaobex://", "file://",
            "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:",
            "urn:epc:", "urn:nfc:"
        };
        const char *prefix = "";
        if (id_code < sizeof(uri_prefixes) / sizeof(uri_prefixes[0]))
            prefix = uri_prefixes[id_code];

        std::string uri(prefix);
        uri.append((const char *)&data[uri_start], uri_len);
        text_out = std::move(uri);
        return true;
    }

    ESP_LOGW(TAG, "unsupported NDEF record type (len=%d, type=0x%02X)",
             type_length, type_length > 0 ? data[type_start] : 0);
    return false;
}

// -------------------------------------------------------------------------
// Cashu token extraction (matches Numo's CashuPaymentHelper.extractCashuToken)
// -------------------------------------------------------------------------

std::string ndef_extract_cashu_token(const std::string &text)
{
    // Direct token
    if (text.compare(0, 6, "cashuA") == 0 || text.compare(0, 6, "cashuB") == 0)
        return text;

    // URL fragment: #token=cashu...
    size_t frag = text.find("#token=cashu");
    if (frag != std::string::npos) {
        size_t start = frag + 7; // skip "#token="
        return text.substr(start);
    }

    // URL parameter: token=cashu...
    size_t param = text.find("token=cashu");
    if (param != std::string::npos) {
        size_t start = param + 6; // skip "token="
        size_t end = text.find_first_of("&#", start);
        if (end == std::string::npos) end = text.size();
        return text.substr(start, end - start);
    }

    // Free-text search for cashuA or cashuB
    for (const char *prefix : {"cashuA", "cashuB"}) {
        size_t pos = text.find(prefix);
        if (pos != std::string::npos) {
            size_t end = pos;
            while (end < text.size()) {
                char c = text[end];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
                    c == '"' || c == '\'' || c == '<' || c == '>' ||
                    c == '&' || c == '#')
                    break;
                end++;
            }
            return text.substr(pos, end - pos);
        }
    }

    return "";
}
