// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 - 2021 Pionix GmbH and Contributors to EVerest
#ifndef YETI_SERIAL
#define YETI_SERIAL

#include "phyverso.pb.h"
#include <date/date.h>
#include <date/tz.h>
#include <sigslot/signal.hpp>
#include <stdexcept>
#include <stdint.h>
#include <termios.h>
#include <unordered_map>
#include <utility>
#include <utils/thread.hpp>
#include <vector>

/// @brief Struct to handle the OpaqueData chunks.
/// This class re-assembles the full data from the chunks.
struct OpaqueDataHandler {

    OpaqueDataHandler(const OpaqueData& chunk) :
        message_id{chunk.id}, chunks_total{chunk.chunks_total}, chunk_current{0} {

        data.reserve(chunks_total * NUM_ELEMENTS);
        insert(chunk);
    }

    /// @brief Insert the new chunk.
    /// @throw std::runtime_error, if the argument is not sound.
    void insert(const OpaqueData& chunk) {
        // Check the input criteria.
        if (chunk.id != message_id || chunk.chunks_total != chunks_total || chunk.chunk_current >= chunk.chunks_total)
            throw std::runtime_error("Invalid input");

        // Insert the missing segments.
        if (chunk.chunk_current < chunk_current)
            return;
        else if (chunk.chunk_current > chunk_current)
            throw std::runtime_error("Invalid input");

        ++chunk_current;
        data.insert(data.end(), std::begin(chunk.data), std::begin(chunk.data) + chunk.data_count);
    }

    /// @brief Returns true if we have gathered all message chunks.
    bool is_complete() const noexcept {
        return chunk_current == chunks_total;
    }

    /// @brief Returns the data. After this call the instance can be destroyed.
    /// @throw std::runtime_error, if the data is incomplete.
    std::vector<int32_t> get_data() {
        if (!is_complete())
            throw std::runtime_error("Incomplete data");
        std::vector<int32_t> out(std::move(data));
        data.clear();
        return out;
    }

private:
    static constexpr size_t NUM_ELEMENTS = sizeof(OpaqueData::data) / sizeof(&OpaqueData::data);

    /// @brief The message id - we use this to identify chunks of our data.
    const unsigned message_id;

    /// @brief The number of total chunks. This let us know when we're done.
    const unsigned chunks_total;

    /// @brief The expected chunk.
    int chunk_current;

    /// @brief The data.
    std::vector<int32_t> data;
};

class evSerial {

public:
    evSerial();
    ~evSerial();

    bool open_device(const char* device, int baud);

    void readThread();
    void run();

    bool reset(const int reset_pin);
    void firmware_update();
    void keep_alive();

    void set_pwm(int target_connector, uint32_t duty_cycle_e2);
    void allow_power_on(int target_connector, bool p);
    void lock(int target_connector, bool _lock);
    void unlock(int target_connector);

    sigslot::signal<KeepAlive> signal_keep_alive;
    sigslot::signal<int, CpState> signal_cp_state;
    sigslot::signal<int, bool> signal_relais_state;
    sigslot::signal<int, ErrorFlags> signal_error_flags;
    sigslot::signal<int, Telemetry> signal_telemetry;
    sigslot::signal<ResetReason> signal_spurious_reset;
    sigslot::signal<> signal_connection_timeout;
    sigslot::signal<int, PpState> signal_pp_state;
    sigslot::signal<FanState> signal_fan_state;
    sigslot::signal<int, LockState> signal_lock_state;
    sigslot::signal<Temperature> signal_temperature;
    sigslot::signal<int, const std::vector<int32_t>&> signal_opaque_data;

private:
    // Serial interface
    bool set_serial_attributes();
    int fd;
    int baud;

    // COBS de-/encoder
    void cobs_decode_reset();
    void handle_packet(uint8_t* buf, int len);
    bool handle_McuToEverest(const uint8_t* buf, const int len);
    bool handle_OpaqueData(const uint8_t* buf, const int len);
    void cobs_decode(uint8_t* buf, int len);
    void cobs_decode_byte(uint8_t byte);
    size_t cobs_encode(const void* data, size_t length, uint8_t* buffer);
    uint8_t msg[2048];
    uint8_t code;
    uint8_t block;
    uint8_t* decode;
    uint32_t crc32(uint8_t* buf, int len);

    // Read thread for serial port
    Everest::Thread read_thread_handle;
    Everest::Thread timeout_detection_thread_handle;

    bool link_write(EverestToMcu* m);
    std::atomic_bool reset_done_flag;
    std::atomic_bool forced_reset;
    /// @brief Maps the connectors to OpaqueDataHandlers.
    std::unordered_map<unsigned, OpaqueDataHandler> opaque_handlers;

    bool serial_timed_out();
    void timeout_detection_thread();
    std::chrono::time_point<date::utc_clock> last_keep_alive_lo_timestamp;
};

#endif
