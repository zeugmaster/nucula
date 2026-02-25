idf_component_register(
    SRCS "pn532.c" "pn532_i2c.c" "pn532_spi.c" "pn532_uart.c"
    INCLUDE_DIRS "include"
    REQUIRES driver
)
