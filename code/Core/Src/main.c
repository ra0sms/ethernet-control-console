/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usb_device.h"
#include "usbd_cdc_if.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "socket.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "stm32f4xx_hal_flash.h"

#define AUTH_ON
#define HTTP_SOCKET     0
#define DATA_BUF_SIZE   16384
#define MAX_SOCK_NUM 8
#define HTTP_PORT 80
#define EEPROM_START_ADDRESS 0x08030000
#define EEPROM_MAGIC_NUMBER 0xABCD1235

uint8_t gDATABUF[DATA_BUF_SIZE];
uint8_t stat;
uint32_t socket_active_since = 0;
char g_http_user[32] = "admin";
char g_http_pass[32] = "password";
char g_http_base64[64] = "";

extern volatile uint8_t usb_rx_buffer[USB_RX_BUFFER_SIZE];
extern volatile uint16_t usb_rx_index;
extern volatile uint8_t usb_rx_ready;
extern volatile uint8_t usb_rx_error;


uint8_t gpio_states[8] = {0};
char last_status_message[128] = {0};
uint8_t operation_mode = 0; // 0 = toggle, 1 = switch
char mode_names[2][16] = {"Toggle Mode", "Switch Mode"};

int ParseIPAddress(const char* ip_str, uint8_t* ip_array);
int ParseMACAddress(const char* mac_str, uint8_t* mac_array);
void ApplyNetworkSettings(void);
void ShowNetworkInfo(void);
void ProcessSetCommand(char* args);
void ProcessGetCommand(char* args);
void ProcessSetButtonCommand(char* args);
void LoadButtonNamesFromEEPROM(void);
void ShowButtonNames(void);
void TrimWhitespace(char* str);

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    wiz_NetInfo netinfo;
    char button_names[8][16];
    char http_user[32];   // ← добавлено
    char http_pass[32];   // ← добавлено
    uint32_t crc;
} EEPROM_Data;
#pragma pack(pop)

char button_names[8][16] = {
    "OUT1", "OUT2", "OUT3", "OUT4",
    "OUT5", "OUT6", "OUT7", "OUT8"
};


const char *http_headers =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n"
    "\r\n";


const char *main_page =
    "<!DOCTYPE html>"
    "<html><head><title>LAN Control Console</title>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
    "<style>"
    "body{font-family:Arial;background:#f0f0f0;text-align:center;padding:20px;}"
    ".container{background:white;border-radius:10px;padding:20px;margin:0 auto;max-width:600px;}"
    ".mode-selector{margin:15px 0;}"
    ".mode-btn{padding:10px 20px;margin:0 5px;border:none;border-radius:5px;cursor:pointer;font-weight:bold;}"
    ".mode-active{background:#007bff;color:white;}"
    ".mode-inactive{background:#6c757d;color:white;}"
    ".btn-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin:20px 0;}"
    ".btn{display:block;padding:20px;border-radius:10px;text-decoration:none;font-size:16px;font-weight:bold;transition:all 0.3s;}"
    ".btn-on{background:#28a745;color:white;box-shadow:0 4px #1e7e34;}"
    ".btn-off{background:#dc3545;color:white;box-shadow:0 4px #a71e2a;}"
    ".btn:hover{opacity:0.9;transform:translateY(-2px);}"
    ".status{margin-top:20px;padding:10px;border-radius:5px;background:#f8f9fa;}"
    "</style>"
    "</head>"
    "<body>"
    "<div class='container'>"
    "<h1>Output Control</h1>";


/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
SPI_HandleTypeDef hspi1;

UART_HandleTypeDef huart1;

/* USER CODE BEGIN PV */
wiz_NetInfo gWIZNETINFO = { .mac = {0x00, 0x08, 0xdc, 0xab, 0xcd, 0xef},
                            .ip = {192, 168, 0, 250},
                            .sn = {255, 255, 255, 0},
                            .gw = {192, 168, 0, 1},
                            .dns = {0, 0, 0, 0},
                            .dhcp = NETINFO_STATIC };



static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const unsigned char* data, size_t input_length, char* output) {
    size_t i = 0, j = 0;
    uint32_t triple;

    while (i + 3 <= input_length) {
        triple = (data[i] << 16) + (data[i+1] << 8) + data[i+2];
        output[j++] = base64_chars[(triple >> 18) & 0x3F];
        output[j++] = base64_chars[(triple >> 12) & 0x3F];
        output[j++] = base64_chars[(triple >>  6) & 0x3F];
        output[j++] = base64_chars[(triple      ) & 0x3F];
        i += 3;
    }

    if (i + 2 == input_length) {
        triple = (data[i] << 16) + (data[i+1] << 8);
        output[j++] = base64_chars[(triple >> 18) & 0x3F];
        output[j++] = base64_chars[(triple >> 12) & 0x3F];
        output[j++] = base64_chars[(triple >>  6) & 0x3F];
        output[j++] = '=';
    } else if (i + 1 == input_length) {
        triple = (data[i] << 16);
        output[j++] = base64_chars[(triple >> 18) & 0x3F];
        output[j++] = base64_chars[(triple >> 12) & 0x3F];
        output[j++] = '=';
        output[j++] = '=';
    }
    output[j] = '\0';
}

void UpdateHTTPBase64(void) {
    char userpass[64];
    int len = snprintf(userpass, sizeof(userpass), "%s:%s", g_http_user, g_http_pass);
    if (len > 0 && len < (int)sizeof(userpass)) {
        base64_encode((const unsigned char*)userpass, len, g_http_base64);
    } else {
        strcpy(g_http_base64, "");
    }
}


int check_authentication(uint8_t* http_request) {
    char* auth_header = strstr((char*)http_request, "Authorization: Basic ");
    if (auth_header == NULL) {
        return 0;
    }
    auth_header += strlen("Authorization: Basic ");
    char* end_of_auth = strchr(auth_header, '\r');
    if (end_of_auth == NULL) {
        return 0;
    }
    int encoded_len = end_of_auth - auth_header;
    char encoded[64] = {0};
    if (encoded_len >= 63) return 0; // safety
    strncpy(encoded, auth_header, encoded_len);
    encoded[encoded_len] = '\0';

    return (strcmp(encoded, g_http_base64) == 0);
}

void send_auth_required(uint8_t socket) {
    const char* auth_page =
        "HTTP/1.1 401 Unauthorized\r\n"
        "WWW-Authenticate: Basic realm=\"LAN Control Console\"\r\n"
        "Content-Type: text/html\r\n"
  //      "Connection: close\r\n"
        "Content-Length: 0\r\n\r\n";

    send(socket, (uint8_t*)auth_page, strlen(auth_page));
}


int _write(int file, char *ptr, int len)
{
    CDC_Transmit_FS((uint8_t*)ptr, len);
    return len;
}


void W5500_Select(void)
{
    HAL_GPIO_WritePin(SPI1_CS_GPIO_Port, SPI1_CS_Pin, GPIO_PIN_RESET);
}

void W5500_Unselect(void)
{
    HAL_GPIO_WritePin(SPI1_CS_GPIO_Port, SPI1_CS_Pin, GPIO_PIN_SET);
}

void W5500_ReadBuff(uint8_t* buff, uint16_t len)
{
    HAL_SPI_Receive(&hspi1, buff, len, 100);
}

void W5500_WriteBuff(uint8_t* buff, uint16_t len)
{
    HAL_SPI_Transmit(&hspi1, buff, len, 100);
}

uint8_t W5500_ReadByte(void)
{
    uint8_t byte;
    W5500_ReadBuff(&byte, sizeof(byte));
    return byte;
}

void W5500_WriteByte(uint8_t byte)
{
    W5500_WriteBuff(&byte, sizeof(byte));
}




uint32_t CalculateXORChecksum(const uint8_t* data, size_t length)
{
    uint32_t checksum = 0;
    for(size_t i = 0; i < length; i++) {
        checksum ^= data[i];
    }
    return checksum;
}


void WriteSettingsToEEPROM(void)
{
    EEPROM_Data eeprom_data = {0};
    eeprom_data.magic = EEPROM_MAGIC_NUMBER;
    memcpy(&eeprom_data.netinfo, &gWIZNETINFO, sizeof(wiz_NetInfo));
    for(int i = 0; i < 8; i++) {
        strncpy(eeprom_data.button_names[i], button_names[i], 15);
        eeprom_data.button_names[i][15] = '\0';
    }
    strncpy(eeprom_data.http_user, g_http_user, 31);
    eeprom_data.http_user[31] = '\0';
    strncpy(eeprom_data.http_pass, g_http_pass, 31);
    eeprom_data.http_pass[31] = '\0';
    size_t checksum_size = sizeof(EEPROM_Data) - sizeof(uint32_t);
    eeprom_data.crc = CalculateXORChecksum((uint8_t*)&eeprom_data, checksum_size);

    printf("XOR Checksum: 0x%08lX\r\n", (unsigned long)eeprom_data.crc);

    HAL_FLASH_Unlock();
    __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_WRPERR |
                          FLASH_FLAG_PGAERR | FLASH_FLAG_PGSERR);

    FLASH_EraseInitTypeDef erase_init = {0};
    erase_init.TypeErase = FLASH_TYPEERASE_SECTORS;
    erase_init.Sector = FLASH_SECTOR_5;
    erase_init.NbSectors = 1;
    erase_init.VoltageRange = FLASH_VOLTAGE_RANGE_3;

    uint32_t sector_error = 0;
    if (HAL_FLASHEx_Erase(&erase_init, &sector_error) != HAL_OK) {
        printf("Flash erase failed\r\n");
        HAL_FLASH_Lock();
        return;
    }
    uint32_t* data_ptr = (uint32_t*)&eeprom_data;
    uint32_t word_count = (sizeof(EEPROM_Data) + 3) / 4;
    uint32_t address = EEPROM_START_ADDRESS;
    for (uint32_t i = 0; i < word_count; i++) {
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, address + i * 4, data_ptr[i]) != HAL_OK) {
            printf("Flash write failed at word %lu\r\n", i);
            break;
        }
    }
    HAL_FLASH_Lock();
    printf("Settings saved to EEPROM\r\n");
}


uint8_t ReadSettingsFromEEPROM(void)
{
    EEPROM_Data* eeprom_data = (EEPROM_Data*)EEPROM_START_ADDRESS;

    printf("Magic in EEPROM: 0x%08X, expected: 0x%08X\r\n",
           (unsigned int)eeprom_data->magic, (unsigned int)EEPROM_MAGIC_NUMBER);

    if(eeprom_data->magic != EEPROM_MAGIC_NUMBER) {
        printf("No valid settings in EEPROM\r\n");
        return 0;
    }

    size_t checksum_size = sizeof(EEPROM_Data) - sizeof(uint32_t);
    uint32_t calculated_checksum = CalculateXORChecksum((uint8_t*)eeprom_data, checksum_size);
    printf("Stored XOR: 0x%08X, Calculated XOR: 0x%08X\r\n",
           (unsigned int)eeprom_data->crc, (unsigned int)calculated_checksum);

    if(eeprom_data->crc != calculated_checksum) {
        printf("EEPROM data corrupted (XOR checksum error)\r\n");
        return 0;
    }

    memcpy(&gWIZNETINFO, &eeprom_data->netinfo, sizeof(wiz_NetInfo));

    for(int i = 0; i < 8; i++) {
        strncpy(button_names[i], eeprom_data->button_names[i], 15);
        button_names[i][15] = '\0';
        printf("Button %d: '%s'\r\n", i, button_names[i]);
        HAL_Delay(1);
    }
    strncpy(g_http_user, eeprom_data->http_user, 31);
    g_http_user[31] = '\0';
    strncpy(g_http_pass, eeprom_data->http_pass, 31);
    g_http_pass[31] = '\0';
    UpdateHTTPBase64();
    printf("Settings loaded from EEPROM\r\n");
    return 1;
}



void LoadDefaultSettings(void)
{
    uint8_t default_mac[] = {0x00, 0x08, 0xDC, 0xAB, 0xCD, 0xEF};
    uint8_t default_ip[] = {192, 168, 0, 250};
    uint8_t default_sn[] = {255, 255, 255, 0};
    uint8_t default_gw[] = {192, 168, 0, 1};
    uint8_t default_dns[] = {8, 8, 8, 8};

    memcpy(gWIZNETINFO.mac, default_mac, 6);
    memcpy(gWIZNETINFO.ip, default_ip, 4);
    memcpy(gWIZNETINFO.sn, default_sn, 4);
    memcpy(gWIZNETINFO.gw, default_gw, 4);
    memcpy(gWIZNETINFO.dns, default_dns, 4);
    gWIZNETINFO.dhcp = NETINFO_STATIC;
    char default_names[8][16] = {
        "OUT1", "OUT2", "OUT3", "OUT4",
        "OUT5", "OUT6", "OUT7", "OUT8"
    };

    for(int i = 0; i < 8; i++) {
        strncpy(button_names[i], default_names[i], 15);
        button_names[i][15] = '\0';
    }
    strncpy(g_http_user, "admin", 31);
    g_http_user[31] = '\0';
    strncpy(g_http_pass, "password", 31);
    g_http_pass[31] = '\0';
    UpdateHTTPBase64();

    printf("Loaded default settings\r\n");
}


void send_web_page(uint8_t socket, const char *base_page, uint8_t gpio_states[], char button_names[][16], uint8_t mode)
{
    char dynamic_content[2048];
    char temp[256];
    strcpy(dynamic_content, base_page);
    strcat(dynamic_content, "<div class='mode-selector'>");

    if (mode == 0) {
        strcat(dynamic_content, "<button class='mode-btn mode-active' onclick='location.href=\"/mode/toggle\"'>Toggle Mode</button>");
        strcat(dynamic_content, "<button class='mode-btn mode-inactive' onclick='location.href=\"/mode/switch\"'>Switch Mode</button>");
    } else {
        strcat(dynamic_content, "<button class='mode-btn mode-inactive' onclick='location.href=\"/mode/toggle\"'>Toggle Mode</button>");
        strcat(dynamic_content, "<button class='mode-btn mode-active' onclick='location.href=\"/mode/switch\"'>Switch Mode</button>");
    }

    strcat(dynamic_content, "</div><div class='btn-grid'>");
    for (int i = 0; i < 8; i++) {
        if (gpio_states[i] == 1) {
            snprintf(temp, sizeof(temp),
                "<a href='/gpio%d/off' class='btn btn-on'>%s ON</a>",
                i, button_names[i]);
        } else {
            snprintf(temp, sizeof(temp),
                "<a href='/gpio%d/on' class='btn btn-off'>%s OFF</a>",
                i, button_names[i]);
        }
        strcat(dynamic_content, temp);
    }
    strcat(dynamic_content, "</div><div class='status'>");
    if (strlen(last_status_message) > 0) {
        strcat(dynamic_content, last_status_message);
    } else {
        strcat(dynamic_content, "Ready");
    }
    strcat(dynamic_content, "</div></div></body></html>");

    char full_page[4096];
    snprintf(full_page, sizeof(full_page), "%s", dynamic_content);

    char header[128];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/html\r\n"
             "Connection: close\r\n"
             "Content-Length: %d\r\n\r\n",
             strlen(full_page));

    send(socket, (uint8_t*)header, strlen(header));
    send(socket, (uint8_t*)full_page, strlen(full_page));
}



void SetGPIO(uint8_t gpio_num, uint8_t state)
{
    switch(gpio_num) {
        case 0:
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0, state ? GPIO_PIN_SET : GPIO_PIN_RESET);
            break;
        case 1:
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_1, state ? GPIO_PIN_SET : GPIO_PIN_RESET);
            break;
        case 2:
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_2, state ? GPIO_PIN_SET : GPIO_PIN_RESET);
            break;
        case 3:
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_3, state ? GPIO_PIN_SET : GPIO_PIN_RESET);
            break;
        case 4:
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_4, state ? GPIO_PIN_SET : GPIO_PIN_RESET);
            break;
        case 5:
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_5, state ? GPIO_PIN_SET : GPIO_PIN_RESET);
            break;
        case 6:
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_6, state ? GPIO_PIN_SET : GPIO_PIN_RESET);
            break;
        case 7:
            HAL_GPIO_WritePin(GPIOB, GPIO_PIN_7, state ? GPIO_PIN_SET : GPIO_PIN_RESET);
            break;
        default:
            printf("Invalid GPIO number: %d\r\n", gpio_num);
    }
}



void ShowHelp(void) {
    HAL_Delay(1);
    printf("Available commands:\r\n");
    HAL_Delay(1);
    printf("  help          - Show this help\r\n");
    HAL_Delay(1);
    printf("  network       - Show network configuration\r\n");
    HAL_Delay(1);
    printf("  buttons       - Show button names\r\n");
    HAL_Delay(1);
    printf("  set [param] [value] - Set network parameter\r\n");
    HAL_Delay(1);
    printf("  setbutton [0-7] [name] - Set button name\r\n");
    HAL_Delay(1);
    printf("  get [param]   - Get network parameter\r\n");
    HAL_Delay(1);
    printf("  save          - Save settings to EEPROM\r\n");
    HAL_Delay(1);
    printf("  load          - Load settings from EEPROM\r\n");
    HAL_Delay(1);
    printf("  set user [name] - Set HTTP username (1-31 chars)\r\n");
    HAL_Delay(1);
    printf("  set pass [pwd]  - Set HTTP password (<=31 chars)\r\n");
    HAL_Delay(1);
    printf("  get user/pass  - Get HTTP credentials\r\n");
    HAL_Delay(1);
    printf("  reset          - Reboot device\r\n");
    HAL_Delay(1);
    printf("  default       - Factory reset to defaults\r\n");
}


int ParseIPAddress(const char* ip_str, uint8_t* ip_array)
{
    int octets[4];
    int count = sscanf(ip_str, "%d.%d.%d.%d",
                      &octets[0], &octets[1], &octets[2], &octets[3]);
    if(count != 4) {
        return 0;
    }

    for(int i = 0; i < 4; i++) {
        if(octets[i] < 0 || octets[i] > 255) {
            return 0;
        }
        ip_array[i] = (uint8_t)octets[i];
    }

    return 1;
}

int ParseMACAddress(const char* mac_str, uint8_t* mac_array)
{
    int bytes[6];
    int count = sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                      &bytes[0], &bytes[1], &bytes[2],
                      &bytes[3], &bytes[4], &bytes[5]);

    if(count != 6) {
        count = sscanf(mac_str, "%x-%x-%x-%x-%x-%x",
                      &bytes[0], &bytes[1], &bytes[2],
                      &bytes[3], &bytes[4], &bytes[5]);
        if(count != 6) {
            return 0;
        }
    }
    for(int i = 0; i < 6; i++) {
        if(bytes[i] < 0 || bytes[i] > 255) {
            return 0;
        }
        mac_array[i] = (uint8_t)bytes[i];
    }
    return 1;
}

void SetIPAddress(char* ip_str)
{
    if(ip_str == NULL) {
        printf("Usage: set ip [x.x.x.x]\r\n");
        return;
    }

    uint8_t new_ip[4];
    if(ParseIPAddress(ip_str, new_ip)) {
        memcpy(gWIZNETINFO.ip, new_ip, 4);
        ApplyNetworkSettings();
        printf("IP address set to: %d.%d.%d.%d\r\n",
               new_ip[0], new_ip[1], new_ip[2], new_ip[3]);
    } else {
        printf("Invalid IP address format. Use: x.x.x.x\r\n");
    }
}

void SetMACAddress(char* mac_str)
{
    if(mac_str == NULL) {
        printf("Usage: set mac [xx:xx:xx:xx:xx:xx]\r\n");
        return;
    }

    uint8_t new_mac[6];
    if(ParseMACAddress(mac_str, new_mac)) {
        memcpy(gWIZNETINFO.mac, new_mac, 6);
        ApplyNetworkSettings();
        printf("MAC address set to: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
               new_mac[0], new_mac[1], new_mac[2],
               new_mac[3], new_mac[4], new_mac[5]);
    } else {
        printf("Invalid MAC format. Use: xx:xx:xx:xx:xx:xx\r\n");
    }
}

void SetSubnetMask(char* subnet_str)
{
    if(subnet_str == NULL) {
        printf("Usage: set subnet [x.x.x.x]\r\n");
        return;
    }

    uint8_t new_sn[4];
    if(ParseIPAddress(subnet_str, new_sn)) {
        memcpy(gWIZNETINFO.sn, new_sn, 4);
        ApplyNetworkSettings();
        printf("Subnet mask set to: %d.%d.%d.%d\r\n",
               new_sn[0], new_sn[1], new_sn[2], new_sn[3]);
    } else {
        printf("Invalid subnet mask format. Use: x.x.x.x\r\n");
    }
}

void SetGateway(char* gw_str)
{
    if(gw_str == NULL) {
        printf("Usage: set gateway [x.x.x.x]\r\n");
        return;
    }

    uint8_t new_gw[4];
    if(ParseIPAddress(gw_str, new_gw)) {
        memcpy(gWIZNETINFO.gw, new_gw, 4);
        ApplyNetworkSettings();
        printf("Gateway set to: %d.%d.%d.%d\r\n",
               new_gw[0], new_gw[1], new_gw[2], new_gw[3]);
    } else {
        printf("Invalid gateway format. Use: x.x.x.x\r\n");
    }
}

void SetDNS(char* dns_str)
{
    if(dns_str == NULL) {
        printf("Usage: set dns [x.x.x.x]\r\n");
        return;
    }

    uint8_t new_dns[4];
    if(ParseIPAddress(dns_str, new_dns)) {
        memcpy(gWIZNETINFO.dns, new_dns, 4);
        ApplyNetworkSettings();
        printf("DNS set to: %d.%d.%d.%d\r\n",
               new_dns[0], new_dns[1], new_dns[2], new_dns[3]);
    } else {
        printf("Invalid DNS format. Use: x.x.x.x\r\n");
    }
}


void ApplyNetworkSettings(void)
{
    wizchip_setnetinfo(&gWIZNETINFO);
    printf("Network settings applied\r\n");
    ShowNetworkInfo();
}

void ShowNetworkInfo(void)
{
    printf("=== Network Configuration ===\r\n");
    printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
           gWIZNETINFO.mac[0], gWIZNETINFO.mac[1], gWIZNETINFO.mac[2],
           gWIZNETINFO.mac[3], gWIZNETINFO.mac[4], gWIZNETINFO.mac[5]);

    printf("IP: %d.%d.%d.%d\r\n",
           gWIZNETINFO.ip[0], gWIZNETINFO.ip[1],
           gWIZNETINFO.ip[2], gWIZNETINFO.ip[3]);

    printf("Subnet: %d.%d.%d.%d\r\n",
           gWIZNETINFO.sn[0], gWIZNETINFO.sn[1],
           gWIZNETINFO.sn[2], gWIZNETINFO.sn[3]);

    printf("Gateway: %d.%d.%d.%d\r\n",
           gWIZNETINFO.gw[0], gWIZNETINFO.gw[1],
           gWIZNETINFO.gw[2], gWIZNETINFO.gw[3]);

    printf("DNS: %d.%d.%d.%d\r\n",
           gWIZNETINFO.dns[0], gWIZNETINFO.dns[1],
           gWIZNETINFO.dns[2], gWIZNETINFO.dns[3]);

    printf("Mode: %s\r\n",
           gWIZNETINFO.dhcp == NETINFO_DHCP ? "DHCP" : "Static");

    printf("HTTP Auth: %s / %s\r\n", g_http_user, g_http_pass);
}

void ProcessSetCommand(char* args)
{
    char* token = strtok(args, " ");
    if(token == NULL) {
        printf("Usage: set [ip|mac|subnet|gateway|dns] [value]\r\n");
        return;
    }

    if(strcmp(token, "ip") == 0) {
        SetIPAddress(strtok(NULL, " "));
    }
    else if(strcmp(token, "mac") == 0) {
        SetMACAddress(strtok(NULL, " "));
    }
    else if(strcmp(token, "subnet") == 0 || strcmp(token, "sn") == 0) {
        SetSubnetMask(strtok(NULL, " "));
    }
    else if(strcmp(token, "gateway") == 0 || strcmp(token, "gw") == 0) {
        SetGateway(strtok(NULL, " "));
    }
    else if(strcmp(token, "dns") == 0) {
        SetDNS(strtok(NULL, " "));
    }
    else if(strcmp(token, "user") == 0) {
        char* new_user = strtok(NULL, "");
        if(new_user) {
            TrimWhitespace(new_user);
            if(strlen(new_user) == 0 || strlen(new_user) > 31) {
                printf("Username must be 1-31 chars\r\n");
                return;
            }
            strncpy(g_http_user, new_user, 31);
            g_http_user[31] = '\0';
            UpdateHTTPBase64();
            printf("HTTP username set to: %s\r\n", g_http_user);
        } else {
            printf("Usage: set user <username>\r\n");
        }
    }
    else if(strcmp(token, "pass") == 0) {
        char* new_pass = strtok(NULL, "");
        if(new_pass) {
            TrimWhitespace(new_pass);
            if(strlen(new_pass) > 31) {
                printf("Password must be <=31 chars\r\n");
                return;
            }
            strncpy(g_http_pass, new_pass, 31);
            g_http_pass[31] = '\0';
            UpdateHTTPBase64();
            printf("HTTP password set to: %s\r\n", g_http_pass);
        } else {
            printf("Usage: set pass <password>\r\n");
        }
    }
    else {
        printf("Unknown parameter: %s\r\n", token);
        printf("Available: ip, mac, subnet, gateway, dns\r\n");
    }
}

void ProcessGetCommand(char* args)
{
    if(strcmp(args, "ip") == 0) {
        printf("IP: %d.%d.%d.%d\r\n",
               gWIZNETINFO.ip[0], gWIZNETINFO.ip[1],
               gWIZNETINFO.ip[2], gWIZNETINFO.ip[3]);
    }
    else if(strcmp(args, "mac") == 0) {
        printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
               gWIZNETINFO.mac[0], gWIZNETINFO.mac[1], gWIZNETINFO.mac[2],
               gWIZNETINFO.mac[3], gWIZNETINFO.mac[4], gWIZNETINFO.mac[5]);
    }
    else if(strcmp(args, "subnet") == 0 || strcmp(args, "sn") == 0) {
        printf("Subnet: %d.%d.%d.%d\r\n",
               gWIZNETINFO.sn[0], gWIZNETINFO.sn[1],
               gWIZNETINFO.sn[2], gWIZNETINFO.sn[3]);
    }
    else if(strcmp(args, "gateway") == 0 || strcmp(args, "gw") == 0) {
        printf("Gateway: %d.%d.%d.%d\r\n",
               gWIZNETINFO.gw[0], gWIZNETINFO.gw[1],
               gWIZNETINFO.gw[2], gWIZNETINFO.gw[3]);
    }
    else if(strcmp(args, "dns") == 0) {
        printf("DNS: %d.%d.%d.%d\r\n",
               gWIZNETINFO.dns[0], gWIZNETINFO.dns[1],
               gWIZNETINFO.dns[2], gWIZNETINFO.dns[3]);
    }
    else if (strcmp(args, "user") == 0) {
        printf("HTTP User: %s\r\n", g_http_user);
    }
    else if (strcmp(args, "pass") == 0) {
        printf("HTTP Pass: %s\r\n", g_http_pass);
    }
    else {
        printf("Usage: get [ip|mac|subnet|gateway|dns]\r\n");
    }
}

void TrimWhitespace(char* str)
{
    char* end;
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return;
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = 0;
}

void ToLowerCase(char* str)
{
    for(int i = 0; str[i]; i++) {
        str[i] = tolower((unsigned char)str[i]);
    }
}

int ParseNumber(const char* str, int* value)
{
    char* endptr;
    long num = strtol(str, &endptr, 10);

    if(endptr == str || *endptr != '\0') {
        return 0;
    }
    *value = (int)num;
    return 1;
}

void SaveSettingsCommand(void)
{
    WriteSettingsToEEPROM();
    printf("Current settings saved to EEPROM\r\n");
}

void LoadSettingsCommand(void)
{
    if(ReadSettingsFromEEPROM()) {
        ApplyNetworkSettings();
        ShowNetworkInfo();
    } else {
        printf("Using current settings\r\n");
    }
}

void FactoryResetCommand(void)
{
    LoadDefaultSettings();
    ApplyNetworkSettings();
    WriteSettingsToEEPROM();
    printf("Factory reset complete. Default settings saved.\r\n");
}

void ParseCommand(char *command) {
	TrimWhitespace(command);
	printf("CMD: %s\r\n", command);
	if (strlen(command) == 0) {
		return;
	}
	//ToLowerCase(command);

	if (strcmp(command, "help") == 0) {
		ShowHelp();
	} else if (strncmp(command, "set ", 4) == 0) {
		ProcessSetCommand(command + 4);
	} else if (strncmp(command, "setbutton ", 10) == 0) {
		ProcessSetButtonCommand(command + 10);
	} else if (strncmp(command, "get ", 4) == 0) {
		ProcessGetCommand(command + 4);
	} else if (strcmp(command, "network") == 0
			|| strcmp(command, "netinfo") == 0) {
		ShowNetworkInfo();
	} else if (strcmp(command, "buttons") == 0) {
		ShowButtonNames();
	} else if (strcmp(command, "save") == 0) {
		SaveSettingsCommand();
	} else if (strcmp(command, "load") == 0) {
		LoadSettingsCommand();
	} else if (strcmp(command, "default") == 0
			|| strcmp(command, "factory") == 0) {
		FactoryResetCommand();
	} else if (strcmp(command, "reset") == 0) {
		printf("Rebooting device...\r\n");
		HAL_Delay(100);
		NVIC_SystemReset();
	} else {
		printf("Unknown command: '%s'\r\n", command);
		printf("Type 'help' for available commands\r\n");
	}
}

uint16_t USB_ReadData(uint8_t* buffer, uint16_t max_len)
{
  __disable_irq();
  uint16_t bytes_to_copy = (usb_rx_index < max_len) ? usb_rx_index : max_len;
  if(bytes_to_copy > 0) {
    memcpy(buffer, (uint8_t*)usb_rx_buffer, bytes_to_copy);
  }
  usb_rx_index = 0;
  usb_rx_ready = 0;
  usb_rx_error = 0;
  __enable_irq();
  return bytes_to_copy;
}

void ProcessUSBData(void)
{
  if(usb_rx_ready) {
    uint8_t buffer[USB_RX_BUFFER_SIZE];
    uint16_t length = USB_ReadData(buffer, sizeof(buffer));

    if(length > 0) {
      buffer[length] = '\0';
      printf("Received: %s\r\n", buffer);
      ParseCommand((char*)buffer);
    }
  }

  if(usb_rx_error) {
    printf("USB RX buffer overflow!\r\n");
    usb_rx_error = 0;
    usb_rx_index = 0;
  }
}


void LoadButtonNamesFromEEPROM(void)
{
    EEPROM_Data* eeprom_data = (EEPROM_Data*)EEPROM_START_ADDRESS;

    if(eeprom_data->magic == EEPROM_MAGIC_NUMBER) {
        for(int i = 0; i < 8; i++) {
            strncpy(button_names[i], eeprom_data->button_names[i], 15);
            button_names[i][15] = '\0';
        }
        printf("Button names loaded from EEPROM\r\n");
    }
}

void ShowButtonNames(void)
{
    printf("=== Button Names ===\r\n");
    for(int i = 0; i < 8; i++) {
    	HAL_Delay(1);
        printf("Button %d: %s\r\n", i, button_names[i]);
        HAL_Delay(1);
    }
}

void SetButtonName(int button_index, char* name)
{
    if(button_index < 0 || button_index > 7) {
        printf("Invalid button index. Must be 0-7\r\n");
        return;
    }

    if(name == NULL || strlen(name) == 0) {
        printf("Name cannot be empty\r\n");
        return;
    }

    if(strlen(name) > 15) {
        printf("Name too long (max 15 characters)\r\n");
        return;
    }

    strncpy(button_names[button_index], name, 15);
    button_names[button_index][15] = '\0';

    printf("Button %d renamed to: %s\r\n", button_index, button_names[button_index]);
}

void ProcessSetButtonCommand(char* args)
{
    char* button_str = strtok(args, " ");
    char* name = strtok(NULL, "");

    if(button_str == NULL || name == NULL) {
        printf("Usage: setbutton [0-7] [name]\r\n");
        return;
    }

    TrimWhitespace(name);
    if(strlen(name) == 0) {
        printf("Name cannot be empty\r\n");
        return;
    }

    int button_index;
    if(!ParseNumber(button_str, &button_index)) {
        printf("Invalid button index: %s\r\n", button_str);
        return;
    }

    SetButtonName(button_index, name);
}

void ensure_socket_closed(uint8_t sock) {
    uint8_t status = getSn_SR(sock);

    switch(status) {
        case SOCK_ESTABLISHED:
            disconnect(sock);
            break;
        case SOCK_CLOSE_WAIT:
            disconnect(sock);
            close(sock);
            break;
        case SOCK_SYNSENT:
        case SOCK_SYNRECV:
        case SOCK_FIN_WAIT:
        case SOCK_CLOSING:
        case SOCK_TIME_WAIT:
        case SOCK_LAST_ACK:
            close(sock);
            break;
        default:
            if(status != SOCK_CLOSED && status != SOCK_INIT) {
                close(sock);
            }
            break;
    }

    if(getSn_SR(sock) != SOCK_CLOSED) {
        close(sock);
    }
}

void EnsureSocketClosedIfNeeded() {
    uint8_t status = getSn_SR(HTTP_SOCKET);
    if (status == SOCK_ESTABLISHED || status == SOCK_CLOSE_WAIT) {
        uint32_t now = HAL_GetTick();
        if (socket_active_since != 0 && (now - socket_active_since > 10000)) {
            printf("Socket stuck >10 seconds, force closing socket %d\r\n", HTTP_SOCKET);
            ensure_socket_closed(HTTP_SOCKET);
            socket_active_since = 0;
        }
    }
}

void ResetW5500(void) {
    HAL_GPIO_WritePin(SPI1_RST_GPIO_Port, SPI1_RST_Pin, GPIO_PIN_RESET);
    HAL_Delay(2);
    HAL_GPIO_WritePin(SPI1_RST_GPIO_Port, SPI1_RST_Pin, GPIO_PIN_SET);
    HAL_Delay(2);
    reg_wizchip_cs_cbfunc(W5500_Select, W5500_Unselect);
    reg_wizchip_spi_cbfunc(W5500_ReadByte, W5500_WriteByte);
    reg_wizchip_spiburst_cbfunc(W5500_ReadBuff, W5500_WriteBuff);

    uint8_t rx_tx_buff_sizes[] = {8, 1, 1, 1, 1, 1, 1, 1};
    wizchip_init(rx_tx_buff_sizes, rx_tx_buff_sizes);
    wizchip_setnetinfo(&gWIZNETINFO);

    ensure_socket_closed(HTTP_SOCKET);
    if (socket(HTTP_SOCKET, Sn_MR_TCP, HTTP_PORT, 0) == HTTP_SOCKET) {
        listen(HTTP_SOCKET);
    }
    printf("W5500 fully reset and reinitialized.\r\n");
}


void CheckW5500(void) {
    static uint32_t last_w5500_check = 0;
    uint32_t now = HAL_GetTick();
    if (now - last_w5500_check < 10000) {
        return;
    }
    uint8_t ver = getVERSIONR();
    if (ver != 0x04) {
        printf("W5500 dead (ver=0x%02X), resetting...\r\n", ver);
        ResetW5500();
        last_w5500_check = now;
        return;
    }
    uint8_t status = getSn_SR(HTTP_SOCKET);
    switch (status) {
        case SOCK_LISTEN:
        case SOCK_INIT:
        case SOCK_CLOSED:
            break;

        case SOCK_ESTABLISHED:
        case SOCK_CLOSE_WAIT:
            if (socket_active_since != 0 && (now - socket_active_since > 15000)) {
                printf("HTTP socket stuck >15s (state=%d), forcing close...\r\n", status);
                ensure_socket_closed(HTTP_SOCKET);
                socket_active_since = 0;

                HAL_Delay(10);
                if (socket(HTTP_SOCKET, Sn_MR_TCP, HTTP_PORT, 0) != HTTP_SOCKET) {
                    printf("Reopen socket failed!\r\n");
                } else if (listen(HTTP_SOCKET) != SOCK_OK) {
                    printf("Re-listen failed!\r\n");
                    close(HTTP_SOCKET);
                } else {
                    printf("HTTP socket reinitialized.\r\n");
                }
            }
            break;

        default:
            printf("HTTP socket in abnormal state: %d, resetting socket...\r\n", status);
            ensure_socket_closed(HTTP_SOCKET);
            socket_active_since = 0;
            close(HTTP_SOCKET);
            HAL_Delay(10);
            if (socket(HTTP_SOCKET, Sn_MR_TCP, HTTP_PORT, 0) == HTTP_SOCKET) {
                if (listen(HTTP_SOCKET) != SOCK_OK) {
                    printf("Listen failed after recovery!\r\n");
                    close(HTTP_SOCKET);
                }
            } else {
                printf("Socket re-creation failed!\r\n");
            }
            break;
    }

    last_w5500_check = now;
}


/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_SPI1_Init(void);
static void MX_TIM11_Init(void);
//static void MX_USART1_UART_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void) {
	/* USER CODE BEGIN 1 */
	/* USER CODE END 1 */

	/* MCU Configuration--------------------------------------------------------*/
	HAL_Init();
	SystemClock_Config();
	MX_GPIO_Init();
	MX_SPI1_Init();
	MX_TIM11_Init();
	MX_USB_DEVICE_Init();

	/* USER CODE BEGIN 2 */
	LL_TIM_EnableCounter(TIM11);
	LL_TIM_EnableIT_UPDATE(TIM11);

	HAL_Delay(2000);

	if (!ReadSettingsFromEEPROM()) {
		LoadDefaultSettings();
		printf("Using default settings\r\n");
	} else {
		printf("Settings loaded from EEPROM\r\n");
	}
	ApplyNetworkSettings();
	UpdateHTTPBase64();

	printf("System initialized\r\n");

	HAL_GPIO_WritePin(SPI1_RST_GPIO_Port, SPI1_RST_Pin, GPIO_PIN_RESET);
	HAL_Delay(10);
	HAL_GPIO_WritePin(SPI1_RST_GPIO_Port, SPI1_RST_Pin, GPIO_PIN_SET);
	HAL_Delay(2000);

	reg_wizchip_cs_cbfunc(W5500_Select, W5500_Unselect);
	reg_wizchip_spi_cbfunc(W5500_ReadByte, W5500_WriteByte);
	reg_wizchip_spiburst_cbfunc(W5500_ReadBuff, W5500_WriteBuff);

	uint8_t rx_tx_buff_sizes[] = { 8, 1, 1, 1, 1, 1, 1, 1 };
	wizchip_init(rx_tx_buff_sizes, rx_tx_buff_sizes);
	wizchip_setnetinfo(&gWIZNETINFO);

	printf("W5500 initialized, IP: %d.%d.%d.%d\r\n", gWIZNETINFO.ip[0],
			gWIZNETINFO.ip[1], gWIZNETINFO.ip[2], gWIZNETINFO.ip[3]);
	if (socket(HTTP_SOCKET, Sn_MR_TCP, 80, 0) != HTTP_SOCKET) {
		printf("Socket creation failed!\r\n");
		while (1) {
			HAL_Delay(1000);
		}
	}

	if (listen(HTTP_SOCKET) != SOCK_OK) {
		printf("Listen failed!\r\n");
		while (1) {
			HAL_Delay(1000);
		}
	}

	printf("HTTP Server listening on port 80...\r\n");

	/* USER CODE END 2 */

	/* Infinite loop */
	while (1) {
		ProcessUSBData();
		CheckW5500();
		EnsureSocketClosedIfNeeded();
		uint8_t status = getSn_SR(HTTP_SOCKET);

		uint32_t now = HAL_GetTick();
		if ((status == SOCK_ESTABLISHED || status == SOCK_CLOSE_WAIT)
				&& socket_active_since != 0) {
			if (now - socket_active_since > 10000) {
				printf("Socket stuck >10s, force closing socket %d\r\n",
						HTTP_SOCKET);
				close(HTTP_SOCKET);
				socket_active_since = 0;
			}
		}
		switch (status) {
		case SOCK_ESTABLISHED: {
			if (socket_active_since == 0) {
				socket_active_since = now;
			}
			uint8_t http_request[1024] = { 0 };
			uint16_t total_len = 0;
			uint32_t recv_start = HAL_GetTick();
			while (total_len < sizeof(http_request) - 1) {
				int16_t len = recv(HTTP_SOCKET, http_request + total_len,
						sizeof(http_request) - total_len - 1);

				if (len > 0) {
					total_len += len;
					recv_start = HAL_GetTick();
					if (total_len >= 4
							&& memcmp(http_request + total_len - 4, "\r\n\r\n",
									4) == 0) {
						break;
					}
				} else if (len == 0) {
					if (HAL_GetTick() - recv_start > 3000) {
						printf("Recv timeout\r\n");
						break;
					}
					HAL_Delay(1);
				} else {
					printf("Recv error: %d\r\n", len);
					break;
				}
			}

			if (total_len > 0) {
				http_request[total_len] = '\0';

#ifdef AUTH_ON
if (strstr((char*) http_request, "GET /favicon.ico") == NULL) {
    if (!check_authentication(http_request)) {
        send_auth_required(HTTP_SOCKET);
        uint32_t start = HAL_GetTick();
        while (getSn_TX_RD(HTTP_SOCKET) != getSn_TX_WR(HTTP_SOCKET)) {
            if (HAL_GetTick() - start > 500 || getSn_SR(HTTP_SOCKET) != SOCK_ESTABLISHED) {
                break;
            }
            HAL_Delay(1);
        }
        goto skip_page_serve_and_close;
    }
}
#endif

				if (strstr((char*) http_request, "GET /mode/toggle")) {
					operation_mode = 0;
					snprintf(last_status_message, sizeof(last_status_message),
							"Toggle mode activated");
					printf("Switch to Toggle mode\r\n");
				} else if (strstr((char*) http_request, "GET /mode/switch")) {
					operation_mode = 1;
					snprintf(last_status_message, sizeof(last_status_message),
							"Switch mode activated");
					printf("Switch to Switch mode\r\n");
				}

				for (int i = 0; i < 8; i++) {
					char on_pattern[20], off_pattern[20];
					snprintf(on_pattern, sizeof(on_pattern), "GET /gpio%d/on",
							i);
					snprintf(off_pattern, sizeof(off_pattern),
							"GET /gpio%d/off", i);

					if (strstr((char*) http_request, on_pattern)) {
						if (operation_mode == 1) {
							for (int j = 0; j < 8; j++) {
								if (j != i) {
									gpio_states[j] = 0;
									SetGPIO(j, 0);
								}
							}
							gpio_states[i] = 1;
							SetGPIO(i, 1);
							snprintf(last_status_message,
									sizeof(last_status_message),
									"GPIO %d turned ON (Switch mode)", i);
							printf("GPIO %d turned ON in Switch mode\r\n", i);
						} else {
							gpio_states[i] = !gpio_states[i];
							SetGPIO(i, gpio_states[i]);
							if (gpio_states[i]) {
								snprintf(last_status_message,
										sizeof(last_status_message),
										"GPIO %d turned ON (Toggle mode)", i);
								printf("GPIO %d turned ON in Toggle mode\r\n",
										i);
							} else {
								snprintf(last_status_message,
										sizeof(last_status_message),
										"GPIO %d turned OFF (Toggle mode)", i);
								printf("GPIO %d turned OFF in Toggle mode\r\n",
										i);
							}
						}
					} else if (strstr((char*) http_request, off_pattern)) {
						gpio_states[i] = 0;
						SetGPIO(i, 0);
						snprintf(last_status_message,
								sizeof(last_status_message),
								"GPIO %d turned OFF", i);
						printf("GPIO %d turned OFF\r\n", i);
					}
				}
				send_web_page(HTTP_SOCKET, main_page, gpio_states, button_names,
						operation_mode);
				ensure_socket_closed(HTTP_SOCKET);
				uint32_t start = HAL_GetTick();
				while (getSn_TX_RD(HTTP_SOCKET) != getSn_TX_WR(HTTP_SOCKET)) {
					if (HAL_GetTick() - start
							> 1000|| getSn_SR(HTTP_SOCKET) != SOCK_ESTABLISHED) {
						break;
					}
					HAL_Delay(1);
				}
			}
			disconnect(HTTP_SOCKET);
			socket_active_since = 0;
			uint32_t close_start = HAL_GetTick();
			while (getSn_SR(HTTP_SOCKET) != SOCK_CLOSED) {
				if (HAL_GetTick() - close_start > 1000) {
					printf("Force close after disconnect timeout\r\n");
					close(HTTP_SOCKET);
					break;
				}
				HAL_Delay(1);
			}
skip_page_serve_and_close:
			break;
		}

		case SOCK_CLOSE_WAIT:
			disconnect(HTTP_SOCKET);
			socket_active_since = 0;
			break;

		case SOCK_CLOSED:
			close(HTTP_SOCKET);
			HAL_Delay(1);
			if (socket(HTTP_SOCKET, Sn_MR_TCP, 80, 0) == HTTP_SOCKET) {
				if (listen(HTTP_SOCKET) != SOCK_OK) {
					printf("Listen failed after socket creation!\r\n");
					close(HTTP_SOCKET);
				}
			} else {
				printf("Socket re-creation failed!\r\n");
				HAL_Delay(1000);
			}
			break;

		case SOCK_INIT:
		case SOCK_LISTEN:
			break;

		default:
			break;
		}

		HAL_Delay(1);
	}
}
/* USER CODE END 3 */


/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE2);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 25;
  RCC_OscInitStruct.PLL.PLLN = 336;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV4;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }

  /** Enables the Clock Security System
  */
  HAL_RCC_EnableCSS();
}

/**
  * @brief SPI1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_SPI1_Init(void)
{

  /* USER CODE BEGIN SPI1_Init 0 */

  /* USER CODE END SPI1_Init 0 */

  /* USER CODE BEGIN SPI1_Init 1 */

  /* USER CODE END SPI1_Init 1 */
  /* SPI1 parameter configuration*/
  hspi1.Instance = SPI1;
  hspi1.Init.Mode = SPI_MODE_MASTER;
  hspi1.Init.Direction = SPI_DIRECTION_2LINES;
  hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi1.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi1.Init.NSS = SPI_NSS_SOFT;
  hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_32;
  hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi1.Init.CRCPolynomial = 10;
  if (HAL_SPI_Init(&hspi1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN SPI1_Init 2 */

  /* USER CODE END SPI1_Init 2 */

}

/**
  * @brief TIM11 Initialization Function
  * @param None
  * @retval None
  */
static void MX_TIM11_Init(void)
{

  /* USER CODE BEGIN TIM11_Init 0 */

  /* USER CODE END TIM11_Init 0 */

  LL_TIM_InitTypeDef TIM_InitStruct = {0};

  /* Peripheral clock enable */
  LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_TIM11);

  /* TIM11 interrupt Init */
  NVIC_SetPriority(TIM1_TRG_COM_TIM11_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));
  NVIC_EnableIRQ(TIM1_TRG_COM_TIM11_IRQn);

  /* USER CODE BEGIN TIM11_Init 1 */

  /* USER CODE END TIM11_Init 1 */
  TIM_InitStruct.Prescaler = 65535;
  TIM_InitStruct.CounterMode = LL_TIM_COUNTERMODE_UP;
  TIM_InitStruct.Autoreload = 999;
  TIM_InitStruct.ClockDivision = LL_TIM_CLOCKDIVISION_DIV1;
  LL_TIM_Init(TIM11, &TIM_InitStruct);
  LL_TIM_EnableARRPreload(TIM11);
  /* USER CODE BEGIN TIM11_Init 2 */

  /* USER CODE END TIM11_Init 2 */

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
/*static void MX_USART1_UART_Init(void)
{

  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }

}*/

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
/* USER CODE BEGIN MX_GPIO_Init_1 */
/* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOA, SPI1_RST_Pin|SPI1_CS_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : LED_Pin */
  GPIO_InitStruct.Pin = LED_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(LED_GPIO_Port, &GPIO_InitStruct);

  GPIO_InitStruct.Pin = GPIO_PIN_0|GPIO_PIN_1|GPIO_PIN_2|GPIO_PIN_3|GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /*Configure GPIO pins : SPI1_RST_Pin SPI1_CS_Pin */
  GPIO_InitStruct.Pin = SPI1_RST_Pin|SPI1_CS_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

/* USER CODE BEGIN MX_GPIO_Init_2 */
/* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
