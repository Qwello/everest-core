// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 - 2021 Pionix GmbH and Contributors to EVerest
#ifndef YETI_SERIAL
#define YETI_SERIAL

#include "phyverso.pb.h"
#include <date/date.h>
#include <date/tz.h>
#include <sigslot/signal.hpp>
#include <stdint.h>
#include <termios.h>
#include <unordered_map>
#include <utils/thread.hpp>

#include <iostream>

/// @brief Struct to handle the PSensors.
///
/// The data from the PSensor comes as chunks over the wire. This class collects
/// the data and returns a full message once all chunk have arrived.
struct PSensorHandler {

    PSensorHandler(const PSensorData& chunk) :
        message_id{chunk.id}, chunks_total{chunk.chunks_total}, chunk_current{0} {

        data.reserve(chunks_total * NUM_ELEMENTS);
        insert(chunk);
    }

    /// @brief Insert the new chunk.
    /// @throw std::runtime_error, if the argument is not sound.
    void insert(const PSensorData& chunk) {
        // Check the input criteria.
        if (chunk.id != message_id || chunk.chunks_total != chunks_total || chunk.chunk_current != chunk_current ||
            chunk.chunk_current >= chunk.chunks_total)
            throw std::runtime_error("Invalid input");

        ++chunk_current;
        data.insert(data.end(), std::begin(chunk.data), std::begin(chunk.data) + chunk.data_count);

        for(const auto& a : data)
            std::cout << a << ",";
        std::cout << std::endl;
    }

    /// @brief Returns true if we have gathered all message chunks.
    bool is_complete() const noexcept {
        return chunk_current == chunks_total;
    }

    /// @brief Returns the data. After this call the instance can be destroyed.
    /// @throw std::runtime_error, if the data is incomplete.
    std::vector<uint16_t>&& get_data() {
        if (!is_complete())
            throw std::runtime_error("Incomplete data");
        return std::move(data);
    }

private:
    static constexpr size_t NUM_ELEMENTS = sizeof(PSensorData::data) / sizeof(&PSensorData::data);

    /// @brief The message id - we use this to identify chunks of our data.
    const unsigned message_id;

    /// @brief The number of total chunks. This let us know when we're done.
    const unsigned chunks_total;

    /// @brief The expected chunk.
    int chunk_current;

    /// @brief The data.
    std::vector<uint16_t> data;
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
    sigslot::signal<int, const std::vector<uint16_t>&> signal_psensor_data;

private:
    // Serial interface
    bool set_serial_attributes();
    int fd;
    int baud;

    // COBS de-/encoder
    void cobs_decode_reset();
    void handle_packet(uint8_t* buf, int len);
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
    /// @brief Maps the connectors to PSensorHandlers.
    std::unordered_map<unsigned, PSensorHandler> psensor_handlers;

    bool serial_timed_out();
    void timeout_detection_thread();
    std::chrono::time_point<date::utc_clock> last_keep_alive_lo_timestamp;
};

#endif
