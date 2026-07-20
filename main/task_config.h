#pragma once

// Stack sizes and priorities for every task the firmware creates, gathered
// so the RAM budget and priority scheme can be compared in one place.
// Values unchanged from their original inline definitions; the console
// task's sizes live in CONSOLE_DEFAULT_CONFIG (console.h).
//
// Priorities: 5 = latency-critical (console echo, NFC exchange),
// 4 = interactive producers (keypad scan, drain), 3 = background.

#define NUCULA_TASK_STACK_NFC        16384
#define NUCULA_TASK_PRIO_NFC         5

#define NUCULA_TASK_STACK_KEYPAD     3072
#define NUCULA_TASK_PRIO_KEYPAD      4

#define NUCULA_TASK_STACK_KEYPAD_UI  4096
#define NUCULA_TASK_PRIO_KEYPAD_UI   3

#define NUCULA_TASK_STACK_WIFI_DRAIN 8192
#define NUCULA_TASK_PRIO_WIFI_DRAIN  4

#define NUCULA_TASK_STACK_WIFI_SUP   4096
#define NUCULA_TASK_PRIO_WIFI_SUP    3

#define NUCULA_TASK_STACK_HTTP_WARM  8192
#define NUCULA_TASK_PRIO_HTTP_WARM   3
