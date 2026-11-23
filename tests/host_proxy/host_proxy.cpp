// A real proxy on the host: ProxyEngine over a POSIX UDP socket, steady_clock, and a
// fake radio that records each transmission and completes it after the frame's
// airtime. test_host_proxy.py runs it against devtools/cs_testserver.py.
//
//   host_proxy --port N --key HEX [--proxy-id HEX] [--boot HEX]
//
// Commands on stdin, one per line:
//   uplink HEX     the radio heard this frame (rssi -90, snr 7.5)
//   quit
// Events on stdout, one per line:
//   ready | connected 0|1 | hello GAP_MS | sent TYPE SEQ | tx HEX | tx_done | log TEXT

#include "proxy_engine.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace esphome::cs_proxy;

namespace {

constexpr uint64_t LOOP_INTERVAL_US = 16000;  // ESPHome's default main-loop interval

bool unhex(const std::string &s, uint8_t *out, size_t n) {
  if (s.size() != 2 * n)
    return false;
  for (size_t i = 0; i < n; i++)
    out[i] = uint8_t(std::strtoul(s.substr(2 * i, 2).c_str(), nullptr, 16));
  return true;
}

std::string hex(const uint8_t *p, size_t n) {
  static const char *const digits = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s += digits[p[i] >> 4];
    s += digits[p[i] & 15];
  }
  return s;
}

class HostIo : public ProxyIo {
 public:
  HostIo(int sock, const sockaddr_in &server, const ProxyConfig &cfg)
      : sock_(sock), server_(server), cfg_(cfg), start_(std::chrono::steady_clock::now()) {}

  uint64_t timer_at{0};  // 0: none
  bool loop_soon{false};
  uint64_t tx_done_at{0};  // 0: radio idle

  // Starts at 1 s: the engine treats 0 as "never".
  uint64_t now_us() override {
    auto d = std::chrono::steady_clock::now() - this->start_;
    return 1000000 + uint64_t(std::chrono::duration_cast<std::chrono::microseconds>(d).count());
  }
  void wait_until(uint64_t t_us) override {
    while (this->now_us() < t_us) {
    }
  }
  uint64_t loop_interval_us() override { return LOOP_INTERVAL_US; }
  bool server_known() override { return true; }
  bool network_up() override { return true; }
  void send_datagram(const uint8_t *data, size_t len) override {
    if (len >= ENV_HEADER)
      std::printf("sent %02x %u\n", data[1], unsigned(uint32_t(data[14]) << 24 | uint32_t(data[15]) << 16 |
                                                     uint32_t(data[16]) << 8 | data[17]));
    if (sendto(this->sock_, data, len, 0, reinterpret_cast<const sockaddr *>(&this->server_), sizeof(this->server_)) <
        0)
      std::printf("log sendto failed\n");
  }
  void rediscover() override { std::printf("log rediscover\n"); }
  uint8_t start_transmit(const uint8_t *frame, size_t len, uint32_t /*timeout_ms*/) override {
    if (this->tx_done_at != 0)
      return TX_RADIO_ERROR;
    this->tx_done_at = this->now_us() + lora_airtime_us(len, this->cfg_.sf, this->cfg_.bw_hz, this->cfg_.cr,
                                                        this->cfg_.preamble);
    std::printf("tx %s\n", hex(frame, len).c_str());
    return TX_SENT;
  }
  void arm_timer(uint64_t wake_us) override { this->timer_at = wake_us; }
  void request_loop() override { this->loop_soon = true; }
  void on_connected(bool connected) override { std::printf("connected %d\n", connected ? 1 : 0); }
  void on_hello(uint16_t gap_ms) override { std::printf("hello %u\n", unsigned(gap_ms)); }
  bool log_enabled(LogLevel level) override { return level <= LogLevel::Debug; }
  void vlog(LogLevel /*level*/, const char *fmt, va_list args) override {
    char line[256];
    std::vsnprintf(line, sizeof(line), fmt, args);
    std::printf("log %s\n", line);
  }

 private:
  int sock_;
  sockaddr_in server_;
  const ProxyConfig &cfg_;
  std::chrono::steady_clock::time_point start_;
};

bool handle_command(const std::string &line, ProxyEngine &engine) {
  if (line == "quit")
    return false;
  if (line.rfind("uplink ", 0) == 0) {
    const std::string h = line.substr(7);
    uint8_t frame[256];
    if (h.size() % 2 != 0 || h.size() / 2 > sizeof(frame) || !unhex(h, frame, h.size() / 2)) {
      std::printf("log bad command\n");
      return true;
    }
    engine.on_packet(frame, h.size() / 2, -90.0f, 7.5f);
    return true;
  }
  std::printf("log unknown command\n");
  return true;
}

}  // namespace

int main(int argc, char **argv) {
  setvbuf(stdout, nullptr, _IOLBF, 0);
  ProxyConfig cfg;
  cfg.region = "US915";
  cfg.frequency_hz = 918500000;
  cfg.sf = 9;
  cfg.bw_hz = 500000;
  cfg.firmware = "cs_proxy host";
  cfg.boot_id = 0x40570001;
  const uint8_t default_id[8] = {0x34, 0x85, 0x18, 0xff, 0xfe, 0x00, 0x00, 0x10};
  std::memcpy(cfg.proxy_id, default_id, 8);
  int port = 0;
  bool have_key = false;
  bool args_ok = argc % 2 == 1;
  for (int i = 1; i + 1 < argc; i += 2) {
    const std::string opt = argv[i], val = argv[i + 1];
    if (opt == "--port") {
      port = std::atoi(val.c_str());
    } else if (opt == "--key") {
      have_key = unhex(val, cfg.key, 16);
    } else if (opt == "--proxy-id") {
      args_ok = args_ok && unhex(val, cfg.proxy_id, 8);
    } else if (opt == "--boot") {
      cfg.boot_id = uint32_t(std::strtoul(val.c_str(), nullptr, 16));
    } else {
      args_ok = false;
    }
  }
  if (!args_ok || port <= 0 || !have_key) {
    std::fprintf(stderr, "usage: %s --port N --key HEX32 [--proxy-id HEX16] [--boot HEX]\n", argv[0]);
    return 2;
  }

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    std::perror("socket");
    return 1;
  }
  fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);
  sockaddr_in server{};
  server.sin_family = AF_INET;
  server.sin_port = htons(uint16_t(port));
  server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  HostIo io(sock, server, cfg);
  ProxyEngine engine(cfg, io);
  std::printf("ready\n");

  std::string pending;
  uint64_t next_loop = io.now_us();
  for (;;) {
    // Sleep until the next pass is due, the timer fires, the radio finishes, or
    // something arrives on stdin or the socket.
    uint64_t wake = next_loop;
    if (io.timer_at != 0 && io.timer_at < wake)
      wake = io.timer_at;
    if (io.tx_done_at != 0 && io.tx_done_at < wake)
      wake = io.tx_done_at;
    if (io.loop_soon)
      wake = 0;
    const uint64_t now = io.now_us();
    const int timeout_ms = wake > now ? int((wake - now + 999) / 1000) : 0;
    pollfd fds[2] = {{STDIN_FILENO, POLLIN, 0}, {sock, POLLIN, 0}};
    poll(fds, 2, timeout_ms);

    // Radio callbacks run between passes, as the radio's own loop() does on a device.
    if (fds[0].revents & (POLLIN | POLLHUP)) {
      char buf[512];
      ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
      if (n <= 0)
        break;
      pending.append(buf, size_t(n));
      size_t nl;
      bool keep_going = true;
      while (keep_going && (nl = pending.find('\n')) != std::string::npos) {
        keep_going = handle_command(pending.substr(0, nl), engine);
        pending.erase(0, nl + 1);
      }
      if (!keep_going)
        break;
    }
    if (io.tx_done_at != 0 && io.now_us() >= io.tx_done_at) {
      io.tx_done_at = 0;
      std::printf("tx_done\n");
      engine.on_transmit_complete(true);
    }

    const uint64_t t = io.now_us();
    const bool timer_due = io.timer_at != 0 && t >= io.timer_at;
    if (t >= next_loop || timer_due || io.loop_soon || (fds[1].revents & POLLIN)) {
      if (timer_due)
        io.timer_at = 0;
      io.loop_soon = false;
      const uint64_t pass = engine.loop_start();
      uint8_t buf[256];
      for (int i = 0; i < 8; i++) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0)
          break;
        engine.on_datagram(buf, size_t(n), pass);
      }
      engine.loop_end();
      next_loop = io.now_us() + LOOP_INTERVAL_US;
    }
  }
  close(sock);
  return 0;
}
