#pragma once

#include "eth_worker.h"
#include "eth_save_process.h"
#include <gui/gui.h>


#define SCREEN_SYMBOLS_WIDTH 30

EthViewProcess* ethernet_view_process_malloc(EthWorkerProcess type, EthernetSaveConfig* config);
void ethernet_view_process_free(EthViewProcess* evp);

void ethernet_view_process_draw(EthViewProcess* process, Canvas* canvas);
void ethernet_view_process_keyevent(EthViewProcess* process, InputKey key);
void ethernet_view_process_print(EthViewProcess* process, const char* str);
void ethernet_view_process_move(EthViewProcess* process, int8_t shift);
void evp_printf(EthViewProcess* process, const char* format, ...);

typedef struct u8x8_struct u8x8_t;
typedef struct u8x8_display_info_struct u8x8_display_info_t;
typedef struct u8x8_tile_struct u8x8_tile_t;

typedef uint8_t (*u8x8_msg_cb)(u8x8_t* u8x8, uint8_t msg, uint8_t arg_int, void* arg_ptr);
typedef uint16_t (*u8x8_char_cb)(u8x8_t* u8x8, uint8_t b);
struct u8x8_struct {
    const u8x8_display_info_t* display_info;
    u8x8_char_cb next_cb;
    u8x8_msg_cb display_cb;
    u8x8_msg_cb cad_cb;
    u8x8_msg_cb byte_cb;
    u8x8_msg_cb gpio_and_delay_cb;
    uint32_t bus_clock;
    const uint8_t* font;
    uint16_t encoding; 
    uint8_t x_offset;
    uint8_t is_font_inverse_mode; 
    uint8_t
        i2c_address;
    uint8_t i2c_started;
    uint8_t utf8_state; 
    uint8_t gpio_result;
    uint8_t debounce_default_pin_state;
    uint8_t debounce_last_pin_state;
    uint8_t debounce_state;
    uint8_t debounce_result_msg;
};

typedef uint8_t u8g2_uint_t; 
typedef int8_t u8g2_int_t; 
typedef int16_t u8g2_long_t;

typedef struct u8g2_struct u8g2_t;
typedef struct u8g2_cb_struct u8g2_cb_t;

typedef void (*u8g2_update_dimension_cb)(u8g2_t* u8g2);
typedef void (*u8g2_update_page_win_cb)(u8g2_t* u8g2);
typedef void (
    *u8g2_draw_l90_cb)(u8g2_t* u8g2, u8g2_uint_t x, u8g2_uint_t y, u8g2_uint_t len, uint8_t dir);
typedef void (*u8g2_draw_ll_hvline_cb)(
    u8g2_t* u8g2,
    u8g2_uint_t x,
    u8g2_uint_t y,
    u8g2_uint_t len,
    uint8_t dir);

typedef uint8_t (*u8g2_get_kerning_cb)(u8g2_t* u8g2, uint16_t e1, uint16_t e2);

struct _u8g2_font_info_t {
    uint8_t glyph_cnt;
    uint8_t bbx_mode;
    uint8_t bits_per_0;
    uint8_t bits_per_1;
    uint8_t bits_per_char_width;
    uint8_t bits_per_char_height;
    uint8_t bits_per_char_x;
    uint8_t bits_per_char_y;
    uint8_t bits_per_delta_x;
    int8_t max_char_width;
    int8_t
        max_char_height; 
    int8_t x_offset;
    int8_t y_offset;
    int8_t ascent_A;
    int8_t descent_g; 
    int8_t ascent_para;
    int8_t descent_para;
    uint16_t start_pos_upper_A;
    uint16_t start_pos_lower_a;
};
typedef struct _u8g2_font_info_t u8g2_font_info_t;


struct _u8g2_font_decode_t {
    const uint8_t* decode_ptr; 
    u8g2_uint_t target_x;
    u8g2_uint_t target_y;
    int8_t x; 
    int8_t y;
    int8_t glyph_width;
    int8_t glyph_height;
    uint8_t decode_bit_pos; 
    uint8_t is_transparent;
    uint8_t fg_color;
    uint8_t bg_color;
};
typedef struct _u8g2_font_decode_t u8g2_font_decode_t;

struct _u8g2_kerning_t {
    uint16_t first_table_cnt;
    uint16_t second_table_cnt;
    const uint16_t* first_encoding_table;
    const uint16_t* index_to_second_table;
    const uint16_t* second_encoding_table;
    const uint8_t* kerning_values;
};
typedef struct _u8g2_kerning_t u8g2_kerning_t;

struct u8g2_cb_struct {
    u8g2_update_dimension_cb update_dimension;
    u8g2_update_page_win_cb update_page_win;
    u8g2_draw_l90_cb draw_l90;
};

typedef u8g2_uint_t (*u8g2_font_calc_vref_fnptr)(u8g2_t* u8g2);

struct u8g2_struct {
    u8x8_t u8x8;
    u8g2_draw_ll_hvline_cb ll_hvline; 
    const u8g2_cb_t* cb;
    uint8_t*
        tile_buf_ptr; 
    uint8_t tile_buf_height;
    uint8_t tile_curr_row;
    u8g2_uint_t pixel_buf_width;
    u8g2_uint_t pixel_buf_height;
    u8g2_uint_t pixel_curr_row; 
    u8g2_uint_t buf_y0;
    u8g2_uint_t buf_y1;
    u8g2_uint_t width;
    u8g2_uint_t height;
    u8g2_uint_t user_x0; 
    u8g2_uint_t user_x1;
    u8g2_uint_t user_y0;
    u8g2_uint_t user_y1;
    const uint8_t* font;
    u8g2_font_calc_vref_fnptr font_calc_vref;
    u8g2_font_decode_t font_decode; 
    u8g2_font_info_t font_info; 
    uint8_t font_height_mode;
    int8_t font_ref_ascent;
    int8_t font_ref_descent;
    int8_t glyph_x_offset;
    uint8_t bitmap_transparency;
    uint8_t draw_color;
    uint8_t is_auto_page_clear;
};
typedef struct EthViewProcessLine {
    char data[SCREEN_SYMBOLS_WIDTH];
} EthViewProcessLine;

struct EthViewProcess {
    EthViewProcessLine* fifo;
    EthWorkerProcess type;
    uint8_t strings_cnt;
    uint8_t carriage;
    uint8_t position;
    uint8_t autofill;
    uint8_t editing;
    uint8_t x;
    uint8_t y;
    void* draw_struct;
};

typedef struct EthViewDrawInit {
    uint8_t* mac;
    uint8_t current_octet;
} EthViewDrawInit;

typedef enum {
    EthViewDrawStaticModeIp,
    EthViewDrawStaticModeMask,
    EthViewDrawStaticModeGateway,
    EthViewDrawStaticModeDNS
} EthViewDrawStaticMode;
typedef struct EthViewDrawStatic {
    EthViewDrawStaticMode current_mode;
    uint8_t* ip;
    uint8_t* mask;
    uint8_t* gateway;
    uint8_t* dns;
    uint8_t current_digit;
    uint8_t editing;
} EthViewDrawStatic;

typedef struct EthViewDrawPing {
    uint8_t current_digit;
    uint8_t* ip;
} EthViewDrawPing;

typedef struct
{
    uint8_t hop_number;
    uint8_t ip[4];
    uint16_t rtt_ms; // Round-trip time in milliseconds
} TracerouteHop;

typedef struct
{
    TracerouteHop hops[30]; // Maximum hops, adjust as needed
    uint8_t hop_count;      // Number of hops recorded
} TracerouteResult;

