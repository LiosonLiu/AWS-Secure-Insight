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

#include <stdlib.h>
#include "atecc508cb.h"
#include "tls/atcatls_cfg.h"
#include "aws_iot_config.h"
#include "aws_net_interface.h"
#include "aws_user_task.h"
#include "aws_client_task.h"
#include "aws/jsonlib/parson.h"


int aws_client_mqtt_packet_id(void)
{
	static uint32_t mPacketIdLast = 0;

	mPacketIdLast = (mPacketIdLast >= 65536) ? 1 : mPacketIdLast + 1;
	return mPacketIdLast;
}

bool aws_client_scan_button(t_aws_kit* kit)
{
	return (kit->button.isPressed[AWS_KIT_BUTTON_1] || kit->button.isPressed[AWS_KIT_BUTTON_2]
			|| kit->button.isPressed[AWS_KIT_BUTTON_3]);
}

int aws_client_mqtt_msg_cb(MqttClient* mqttCli, MqttMessage* msg, uint8_t new, uint8_t done)
{
	int ret = AWS_E_SUCCESS;
	t_aws_kit* kit = aws_kit_get_instance();

	if (!mqttCli || !msg) return AWS_E_CLI_SUB_FAILURE;

#ifdef AWS_KIT_DEBUG
	AWS_INFO("Subscribed Topic = %s\r\nMessage = %s", msg->topic_name, msg->buffer);
#else
	AWS_INFO("Subscribed delta topic");
#endif
	if(strncmp((const char*)kit->topic.updateDeltaTopic, (const char*)msg->topic_name, 
				strlen((const char*)kit->topic.updateDeltaTopic)) == 0) {

		char reportedMsg[AWS_MQTT_PAYLOAD_MAX];
		char intBuf[0], desiredBuf[16], reportedBuf[32];
		char* serializedStr = NULL;
		JSON_Value* jPubVal = NULL;
		JSON_Value* jSubVal = json_parse_string((const char*)msg->buffer);
		JSON_Object* jObject = json_value_get_object(jSubVal);

		for (uint8_t i = AWS_KIT_LED_1; i < AWS_KIT_LED_MAX; i++) {
			strcpy((char*)desiredBuf, (const char*)"state.led");
			strcat((char*)desiredBuf, (const char*)itoa(i + 1, (char*)intBuf, 10));
			if(json_object_dotget_string(jObject, (const char*)desiredBuf) != NULL) {
				kit->led.isDesired[i] = true;
				if(strcmp(json_object_dotget_string(jObject, (const char*)desiredBuf), "on") == 0) {
					kit->led.state[i] = true;
					kit->led.turn_on((uint8_t)i + 1);
				} else if (strcmp(json_object_dotget_string(jObject, (const char*)desiredBuf), "off") == 0) {
					kit->led.state[i] = false;
					kit->led.turn_off((uint8_t)i + 1);
				}
			}
		}

		jPubVal = json_value_init_object();
		jObject = json_value_get_object(jPubVal);

		for (uint8_t i = AWS_KIT_LED_1; i < AWS_KIT_LED_MAX; i++) {
			strcpy(reportedBuf, (const char*)"state.reported.led");
			strcat(reportedBuf, (const char*)itoa(i + 1, (char*)intBuf, 10));
			if(kit->led.isDesired[i]) {
				json_object_dotset_string(jObject, (const char*)reportedBuf, kit->led.state[i] ? "on" : "off");
			}
			kit->led.isDesired[i] = false;
		}

		serializedStr = json_serialize_to_string((const JSON_Value *)jPubVal);
		strcpy(reportedMsg, (const char*)serializedStr);
		json_free_serialized_string(serializedStr);

		MqttPublish publish;
		memset(&publish, 0, sizeof(MqttPublish));
		publish.retain = 0;
		publish.qos = 0;
		publish.duplicate = 0;
		publish.topic_name = (const char*)kit->topic.updateTopic;
		publish.packet_id = aws_client_mqtt_packet_id();
		publish.buffer = (byte*)reportedMsg;
		publish.total_len = strlen((char*)publish.buffer);
		ret = MqttClient_Publish(&kit->client, &publish);
		if (ret != MQTT_CODE_SUCCESS) {
			AWS_ERROR("Failed to publish update topic!(%d)", ret);
			ret = AWS_E_CLI_PUB_FAILURE;
		}

		json_value_free(jSubVal);
		json_value_free(jPubVal);

    }  

	return ret;
}

int aws_client_tls_cb(MqttClient* mqttCli)
{
	int ret = AWS_E_SUCCESS;
	uint8_t* cert_chain = NULL;
	t_aws_kit* kit = aws_kit_get_instance();

	do {

#ifdef AWS_KIT_DEBUG
		wolfSSL_Debugging_ON();
#endif
		mqttCli->tls.ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
		if (mqttCli->tls.ctx == NULL) {
			AWS_ERROR("Failed to init context!");
			break;
		}

		ret = wolfSSL_CTX_set_cipher_list(mqttCli->tls.ctx, AWS_IOT_CIPHER_SPEC);
		if (ret != SSL_SUCCESS) {
			AWS_ERROR("Failed to set cipher!");
			break;
		}

		ret = wolfSSL_CTX_load_verify_buffer(mqttCli->tls.ctx, AWS_IOT_ROOT_CERT, sizeof(AWS_IOT_ROOT_CERT), SSL_FILETYPE_PEM);
		if (ret != SSL_SUCCESS) {
			AWS_ERROR("Failed to set root cert!");
			break;
		}

		cert_chain = (uint8_t*)malloc(kit->cert.signerCertLen + kit->cert.devCertLen);
		memcpy(&cert_chain[0], kit->cert.devCert, kit->cert.devCertLen);
		memcpy(&cert_chain[kit->cert.devCertLen], kit->cert.signerCert, kit->cert.signerCertLen);
		ret = wolfSSL_CTX_use_certificate_chain_buffer(mqttCli->tls.ctx, cert_chain, kit->cert.signerCertLen + kit->cert.devCertLen);
		if (ret != SSL_SUCCESS) {
			AWS_ERROR("Failed to set cert chain!");
			break;
		}

		ret = wolfSSL_CTX_use_PrivateKey_buffer(mqttCli->tls.ctx, AWS_TEMP_DEV_KEY, sizeof(AWS_TEMP_DEV_KEY), SSL_FILETYPE_PEM);
		if (ret != SSL_SUCCESS) {
			AWS_ERROR("Failed to set fake key!");
			break;
		}

		wolfSSL_CTX_set_verify(mqttCli->tls.ctx, SSL_VERIFY_PEER, NULL);
		wolfSSL_CTX_SetEccSignCb(mqttCli->tls.ctx, atca_tls_sign_certificate_cb);
		wolfSSL_CTX_SetEccVerifyCb(mqttCli->tls.ctx, atca_tls_verify_signature_cb);	
		wolfSSL_CTX_SetEccPmsCb(mqttCli->tls.ctx, atca_tls_create_pms_cb);

	} while(0);

	if (cert_chain) free(cert_chain);

	return ret;
}

int aws_client_init_mqtt_client(t_aws_kit* kit)
{
	int ret = AWS_E_FAILURE;
	MqttConnect mqttCon;
	MqttMessage mqttMsg;

	do {

		kit->net.connect = aws_net_connect_cb;
		kit->net.read = aws_net_receive_packet_cb;
		kit->net.write = aws_net_send_packet_cb;
		kit->net.disconnect = aws_net_disconnect_cb;
		kit->net.context = malloc(sizeof(SOCKET));
		if (kit->net.context == NULL) { 
			AWS_ERROR("Failed to allocate heap!");
			break;
		}

		memset(kit->net.context, 0, sizeof(SOCKET));
		ret = MqttClient_Init(&kit->client, &kit->net, aws_client_mqtt_msg_cb, kit->buffer.mqttTxBuf, sizeof(kit->buffer.mqttTxBuf), 
						kit->buffer.mqttRxBuf, sizeof(kit->buffer.mqttRxBuf),  AWS_MQTT_CMD_TIMEOUT_MS);
		if (ret != MQTT_CODE_SUCCESS) {
			AWS_ERROR("Error(%d) : Failed to initialize MQTT client!", ret);
			break;
		}

		ret = MqttClient_NetConnect(&kit->client, (const char *)kit->user.host, AWS_IOT_MQTT_PORT, 
						AWS_NET_CONN_TIMEOUT_MS, TRUE, aws_client_tls_cb);
		if (ret != MQTT_CODE_SUCCESS) {
			AWS_ERROR("Error(%d) : Failed to connect to Host!", ret);
			break;
		}

		memset(&mqttCon, 0, sizeof(MqttConnect));
		memset(&mqttMsg, 0, sizeof(MqttMessage));
        mqttCon.keep_alive_sec = AWS_IOT_KEEP_ALIVE_SEC;
        mqttCon.clean_session = 1;
        mqttCon.client_id = (const char*)kit->user.clientID;
		mqttCon.lwt_msg = &mqttMsg;
		ret = MqttClient_Connect(&kit->client, &mqttCon);
		if (ret != MQTT_CODE_SUCCESS) {
			AWS_ERROR("Error(%d) : Failed to receive CONNACK!", ret);
			break;
		}

		aws_kit_init_timer(&kit->keepAlive);
		aws_kit_countdown_sec(&kit->keepAlive, AWS_IOT_KEEP_ALIVE_SEC);
	} while(0);

	return ret;
}

int aws_client_mqtt_subscribe(t_aws_kit* kit)
{
	int ret = AWS_E_FAILURE;
	MqttSubscribe mqttSub;
	MqttTopic topics[1];

	snprintf((char*)kit->topic.updateDeltaTopic, sizeof(kit->topic.updateDeltaTopic), AWS_IOT_UPDATE_DELTA_TOPIC, kit->user.thing);
	topics[0].topic_filter = (const char*)kit->topic.updateDeltaTopic;
	topics[0].qos = MQTT_QOS_0;

	memset(&mqttSub, 0, sizeof(MqttSubscribe));
	mqttSub.packet_id = aws_client_mqtt_packet_id();
	mqttSub.topic_count = sizeof(topics)/sizeof(MqttTopic);
	mqttSub.topics = topics;
	ret = MqttClient_Subscribe(&kit->client, &mqttSub);
	if (ret != MQTT_CODE_SUCCESS) {
		AWS_ERROR("Failed to subscribe delta topic!(%d)", ret);
	}

	return ret;
}

int aws_client_mqtt_publish(t_aws_kit* kit)
{
	int ret = AWS_E_FAILURE;
	char pubMsg[AWS_MQTT_PAYLOAD_MAX];
	MqttPublish mqttPub;

	snprintf((char*)kit->topic.updateTopic, sizeof(kit->topic.updateTopic), AWS_IOT_UPDATE_TOPIC, kit->user.thing);
	mqttPub.retain = 0;
	mqttPub.qos = MQTT_QOS_0;
	mqttPub.duplicate = 0;
	mqttPub.topic_name = (const char*)kit->topic.updateTopic;
	mqttPub.packet_id = aws_client_mqtt_packet_id();
	sprintf(pubMsg, AWS_IOT_LED_PUB_MESSAGE, kit->led.state[AWS_KIT_LED_1] ? "on" : "off", 
			kit->led.state[AWS_KIT_LED_2] ? "on" : "off", kit->led.state[AWS_KIT_LED_3] ? "on" : "off");
	mqttPub.buffer = (byte *)pubMsg;
	mqttPub.total_len = strlen((char *)mqttPub.buffer);
	ret = MqttClient_Publish(&kit->client, &mqttPub);
	if (ret != MQTT_CODE_SUCCESS) {
		AWS_ERROR("Failed to publish the update topic(%d)", ret);
		return AWS_E_CLI_PUB_FAILURE;
	}
#ifdef AWS_KIT_DEBUG
	AWS_INFO("Published LED Message : %s", pubMsg);
#else
	AWS_INFO("Published LED Message");
#endif
	sprintf(pubMsg, AWS_IOT_BUT_PUB_MESSAGE, "up", "up", "up");
	mqttPub.buffer = (byte *)pubMsg;
	mqttPub.total_len = strlen((char *)mqttPub.buffer);
	ret = MqttClient_Publish(&kit->client, &mqttPub);
	if (ret != MQTT_CODE_SUCCESS) {
		AWS_ERROR("Failed to publish the update topic(%d)", ret);
		ret = AWS_E_CLI_PUB_FAILURE;
	}
#ifdef AWS_KIT_DEBUG
	AWS_INFO("Published BUTTON Message : %s", pubMsg);
#else
	AWS_INFO("Published BUTTON Message");
#endif

	return ret;
}

int aws_client_mqtt_wait_msg(t_aws_kit* kit)
{
	int ret = AWS_E_FAILURE;

	if (aws_kit_timer_expired(&kit->keepAlive)) {
		kit->nonBlocking = true;
		ret = MqttClient_Ping(&kit->client);
		if (ret != MQTT_CODE_SUCCESS) {
			AWS_ERROR("Failed to send PING packet!(%d)", ret);
			return ret;
		}
		kit->nonBlocking = false;
		aws_kit_init_timer(&kit->keepAlive);
		aws_kit_countdown_sec(&kit->keepAlive, AWS_IOT_KEEP_ALIVE_SEC);
	}

	ret = MqttClient_WaitMessage(&kit->client, AWS_MQTT_CMD_TIMEOUT_MS);
	if (ret == MQTT_CODE_ERROR_TIMEOUT) {
		AWS_INFO("Polling message to subscribe");		
		if (aws_client_scan_button(kit)) {

			char* serializedStr = NULL;
			char reportedMsg[AWS_MQTT_PAYLOAD_MAX], intBuf[0], reportedBuf[32] = "state.reported.button";
			JSON_Value* jPubVal = json_value_init_object();
			JSON_Object* jObject = json_value_get_object(jPubVal);
			MqttPublish publish;

			for (uint8_t i = AWS_KIT_BUTTON_1; i < AWS_KIT_BUTTON_MAX; i++) {
				if (kit->button.isPressed[i]) {
					strcat((char*)reportedBuf, (const char*)itoa(i + 1, (char*)intBuf, 10));
					json_object_dotset_string(jObject, (const char*)reportedBuf, (kit->button.state[i] ? "up" : "down"));
					kit->button.isPressed[i] = false;
					kit->button.state[i] = !kit->button.state[i];
					break;
				}
			}

			serializedStr = json_serialize_to_string((const JSON_Value *)jPubVal);
			strcpy(reportedMsg, (const char*)serializedStr);
			json_free_serialized_string(serializedStr);

			memset(&publish, 0, sizeof(MqttPublish));
			publish.retain = 0;
			publish.qos = 0;
			publish.duplicate = 0;
			/* Build list of topics */
			publish.topic_name = (const char*)kit->topic.updateTopic;
			publish.packet_id = aws_client_mqtt_packet_id();
			publish.buffer = (byte *)reportedMsg;
			publish.total_len = strlen((char *)publish.buffer);
			kit->nonBlocking = true;
			ret = MqttClient_Publish(&kit->client, &publish);
			if (ret != MQTT_CODE_SUCCESS) {
				AWS_ERROR("Failed to publish the update topic!(%d)", ret);
			}
			kit->nonBlocking = false;
			json_value_free(jPubVal);
#ifdef AWS_KIT_DEBUG
			AWS_INFO("Published Topic = %s\r\nMessage = %s", publish.topic_name, publish.buffer);
#else
			AWS_INFO("Published the update topic");
#endif
		}
	}

	return ret;
}

/**
 * \brief main state machine for AWS client.
 */
void aws_client_state_machine(t_aws_kit* kit)
{
	int ret = AWS_E_SUCCESS;
	static bool errorNoti = false;
	static uint8_t currState = CLIENT_STATE_INIT_MQTT_CLIENT;
	uint8_t nextState = CLIENT_STATE_INVALID;

	switch (currState)
	{
		case CLIENT_STATE_INIT_MQTT_CLIENT:
			ret = aws_client_init_mqtt_client(kit);
			if (ret != AWS_E_SUCCESS) {
				if (!errorNoti) {
					errorNoti = true;
					kit->errState = AWS_EX_TLS_FAILURE;
					aws_user_exception_init_timer(kit);
				}
				nextState = CLIENT_STATE_INIT_MQTT_CLIENT;
			} else {
				if (kit->errState == AWS_EX_TLS_FAILURE)
					kit->errState = AWS_EX_NONE;
				errorNoti = false;
				nextState = CLIENT_STATE_MQTT_SUBSCRIBE;
			}
			break;

		case CLIENT_STATE_MQTT_SUBSCRIBE:
			ret = aws_client_mqtt_subscribe(kit);
			if (ret != AWS_E_SUCCESS) {
				if (!errorNoti) {
					errorNoti = true;
					kit->errState = AWS_EX_MQTT_FAILURE;
					aws_user_exception_init_timer(kit);
				}
				nextState = CLIENT_STATE_MQTT_SUBSCRIBE;
			} else {
				if (kit->errState == AWS_EX_MQTT_FAILURE)
					kit->errState = AWS_EX_NONE;
				errorNoti = false;
				nextState = CLIENT_STATE_MQTT_PUBLISH;
			}
			break;

		case CLIENT_STATE_MQTT_PUBLISH:
			ret = aws_client_mqtt_publish(kit);
			if (ret != AWS_E_SUCCESS) {
				if (!errorNoti) {
					errorNoti = true;
					kit->errState = AWS_EX_MQTT_FAILURE;
					aws_user_exception_init_timer(kit);
				}
				nextState = CLIENT_STATE_MQTT_PUBLISH;
			} else {
				if (kit->errState == AWS_EX_MQTT_FAILURE)
					kit->errState = AWS_EX_NONE;
				nextState = CLIENT_STATE_MQTT_WAIT_MESSAGE;
			}
			break;

		case CLIENT_STATE_MQTT_WAIT_MESSAGE:
			aws_client_mqtt_wait_msg(kit);
			nextState = CLIENT_STATE_MQTT_WAIT_MESSAGE;
			break;

		case CLIENT_STATE_INVALID:
			nextState = CLIENT_STATE_INVALID;
			break;

		default:
			break;
	}

	currState = kit->clientState = nextState;
}

void aws_client_task(void *params)
{
	t_aws_kit* kit = aws_kit_get_instance();

	for (;;) {

		aws_client_state_machine(kit);

		vTaskDelay(AWS_CLIENT_TASK_DELAY);
	}
}
