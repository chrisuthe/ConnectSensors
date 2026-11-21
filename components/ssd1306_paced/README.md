# `ssd1306_paced` ESPHome component

A drop-in replacement for ESPHome's `ssd1306_i2c` that never pushes a whole frame
in one main-loop pass.

ESPHome runs every component in one loop task, and `ssd1306_i2c` sends the full
frame synchronously: on a Heltec V3 (ESP32-S3, 800 kHz I2C) one redraw holds the
loop for about 22 ms, and the radio and network wait behind it. Here `update()`
only renders into the frame buffer; `loop()` then sends one changed 8-row page per
pass, about 2 ms each, and stops looping once the panel matches the buffer. Pages
that a render did not change are never sent.

```yaml
external_components:
  - source: github://chrisuthe/ConnectSensors@main
    components: [ssd1306_paced]

display:
  - platform: ssd1306_paced
    model: SSD1306_128X64
    address: 0x3C
    # every other ssd1306_i2c option works the same
```

SSD1306 and SSD1305 models only (horizontal addressing); SH1106 and SH1107 are
rejected at config time. A frame reaches the panel over a few loop passes, so a
fast-changing screen can briefly show rows from two renders.
