/**
 *
 * \file
 *
 * \brief AWS IoT Demo kit.
 *
 * Copyright (c) 2014-2016 Atmel Corporation. All rights reserved.
 *
 * \asf_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel microcontroller product.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \asf_license_stop
 *
 */

#ifndef AWS_KIT_OBJECT_H_
#define AWS_KIT_OBJECT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <asf.h>
#include "aws_kit_debug.h"
#include "aws_kit_timer.h"
#include "wolfmqtt/mqtt_client.h"
#include "wolfmqtt/mqtt_socket.h"

#define AWS_ROOT_CERT_MAX					(2048)
#define AWS_CERT_LENGH_MAX					(1024)
#define AWS_WIFI_SSID_MAX					(32)
#define AWS_WIFI_PSK_MAX					(32)
#define AWS_HOST_ADDR_MAX					(64)
#define AWS_THING_NAME_MAX					(32)
#define AWS_CLIENT_NAME_MAX					(12)
#define AWS_MQTT_BUF_SIZE_MAX				(1024)
#define AWS_MQTT_TOPIC_MAX					(128)

#define AWS_USER_DATA_OFFSET_SSID_LEN		(0)
#define AWS_USER_DATA_OFFSET_SSID			(4)
#define AWS_USER_DATA_OFFSET_PSK_LEN		(36)
#define AWS_USER_DATA_OFFSET_PSK			(40)
#define AWS_USER_DATA_OFFSET_HOST_LEN		(72)
#define AWS_USER_DATA_OFFSET_HOST			(76)
#define AWS_USER_DATA_OFFSET_THING_LEN		(140)
#define AWS_USER_DATA_OFFSET_THING			(144)
#define AWS_USER_DATA_OFFSET_MAX			(176)

enum { 
	AWS_KIT_BUTTON_1,
	AWS_KIT_BUTTON_2,
	AWS_KIT_BUTTON_3,
	AWS_KIT_BUTTON_MAX,
};

enum { 
	AWS_KIT_LED_1,
	AWS_KIT_LED_2,
	AWS_KIT_LED_3,
	AWS_KIT_LED_MAX,
};

enum { 
	AWS_BUTTON_RELEASED,
	AWS_BUTTON_PRESSED,
	AWS_BUTTON_MAX,
};

typedef enum { 
	AWS_EX_NONE,
	AWS_EX_UNPROVISIONED_CRYPTO,
	AWS_EX_UNAVAILABLE_WIFI,
	AWS_EX_TLS_FAILURE,
	AWS_EX_MQTT_FAILURE,
	AWS_EX_MAX,
} KIT_ERROR_STATE;

typedef enum { 
	NOTI_INVALID,
	NOTI_RUN_MQTT_CLIENT,
	NOTI_RESET_USER_DATA,
	NOTI_MAX
} KIT_NOTI_STATE;

typedef enum { 
	CLIENT_STATE_INVALID,
	CLIENT_STATE_INIT_MQTT_CLIENT,
	CLIENT_STATE_MQTT_SUBSCRIBE,
	CLIENT_STATE_MQTT_PUBLISH,
	CLIENT_STATE_MQTT_WAIT_MESSAGE,
	CLIENT_STATE_MAX
} KIT_CLIENT_STATE;

typedef enum { 
	MAIN_STATE_INVALID,
	MAIN_STATE_INIT_KIT,
	MAIN_STATE_CHECK_KIT,
	MAIN_STATE_PROVISIONING,
	MAIN_STATE_RUN_KIT,
	MAIN_STATE_MAX
} KIT_MAIN_STATE;

typedef struct AWS_CERT {
	uint32_t signerCertLen;
	uint8_t signerCert[AWS_CERT_LENGH_MAX];
	uint32_t devCertLen;
	uint8_t devCert[AWS_CERT_LENGH_MAX];
} t_awsCert;

typedef struct AWS_USER_DATA {
	uint32_t ssidLen;
	uint8_t ssid[AWS_WIFI_SSID_MAX];
	uint32_t pskLen;
	uint8_t psk[AWS_WIFI_PSK_MAX];
	uint32_t hostLen;
	uint8_t host[AWS_HOST_ADDR_MAX];
	uint32_t thingLen;
	uint8_t thing[AWS_THING_NAME_MAX];
	uint32_t port;
	uint32_t clientIDLen;
	uint8_t clientID[AWS_CLIENT_NAME_MAX];
} t_awsUserData;

typedef struct AWS_MQTT_BUFFER {
	uint8_t mqttTxBuf[AWS_MQTT_BUF_SIZE_MAX];
	uint8_t mqttRxBuf[AWS_MQTT_BUF_SIZE_MAX];
} t_awsMqttBuffer;

typedef struct AWS_TOPIC_BUFFER {
	uint8_t updateDeltaTopic[AWS_MQTT_TOPIC_MAX];
	uint8_t updateTopic[AWS_MQTT_TOPIC_MAX];
} t_awsMqttTopic;

typedef int (*LED_ON)(uint8_t id);
typedef int (*LED_OFF)(uint8_t id);

typedef struct AWS_LED_STATE {
	bool isDesired[AWS_KIT_LED_MAX];
	bool state[AWS_KIT_LED_MAX];
	LED_ON turn_on;
	LED_OFF turn_off;
} t_awsLedState;

typedef struct AWS_BUTTON_STATE {
	bool isPressed[AWS_KIT_BUTTON_MAX];
	bool state[AWS_KIT_BUTTON_MAX];
} t_awsButtonState;

typedef struct AWS_KIT {
	bool nonBlocking;
	bool pushButtonState;
	xQueueHandle notiQueue;
	xQueueHandle buttonQueue;
	KIT_NOTI_STATE noti;
	KIT_CLIENT_STATE clientState;
	KIT_MAIN_STATE mainState;
	KIT_ERROR_STATE	errState;
	t_awsCert cert;
	t_awsUserData user;
	t_awsMqttBuffer buffer;
	t_awsMqttTopic topic;
	t_awsLedState led;
	t_awsButtonState button;
	Timer keepAlive;
	Timer buttonISR;
	Timer resetISR;
	Timer exceptionTimer;
	MqttNet net;
	MqttClient client;
} t_aws_kit;

t_aws_kit* aws_kit_get_instance(void);

#ifdef __cplusplus
}
#endif

#endif /* AWS_KIT_OBJECT_H_ */
