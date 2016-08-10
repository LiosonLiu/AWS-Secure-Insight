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

#include "aws_client_task.h"
#include "aws_user_task.h"
#include "aws_prov_task.h"
#include "aws_main_task.h"
#include "aws_net_interface.h"
#include "aws_kit_debug.h"
#include "cryptoauthlib.h"
#include "tls/atcatls_cfg.h"
#include "atecc508cb.h"

xTaskHandle mainTaskHandler;
xTaskHandle provTaskHandler;
xTaskHandle userTaskHandler;
xTaskHandle clientTaskHandler;

int aws_main_wait_notification(t_aws_kit* kit)
{
	int ret = AWS_E_FAILURE;
	uint8_t queueBuf[1];

	while (xQueueReceive(kit->notiQueue, queueBuf, 0)) {
		if(queueBuf[0] == NOTI_RESET_USER_DATA) {
			AWS_INFO("Reset SSID and PWD");	
			vTaskSuspend(clientTaskHandler);
			ret = aws_main_reset_wifi_credential(kit);
			if (ret != ATCA_SUCCESS) {
				AWS_ERROR("Failed to reset user data!(%d)", ret);
				ret = AWS_E_CRYPTO_FAILURE;
				break;
			}
			aws_kit_software_reset();
		}

		if (queueBuf[0] == NOTI_RUN_MQTT_CLIENT)
			ret = AWS_E_SUCCESS;
	}

	return ret;
}

int aws_main_init_kit(t_aws_kit* kit)
{
	int ret = AWS_E_FAILURE;
	bool lockstate = false;
	uint8_t revision[4];

	do {

		kit->errState = AWS_EX_NONE;

		cfg_ateccx08a_i2c_default.atcai2c.slave_address = DEVICE_I2C;
		atcab_init( &cfg_ateccx08a_i2c_default );

		ret = atcab_is_locked(LOCK_ZONE_CONFIG, &lockstate);
		if (ret != ATCA_SUCCESS) {
			AWS_ERROR("Failed to read config zone of ATECC508(%d)", ret);
			ret = AWS_E_CRYPTO_FAILURE;
			break;
		}
		if (!lockstate)	{
			AWS_ERROR("Un-Provisioned ATECC508");
			ret = AWS_E_CRYPTO_FAILURE;
			break;
		}

		ret = atcab_is_locked(LOCK_ZONE_DATA, &lockstate);
		if (ret != ATCA_SUCCESS) {
			AWS_ERROR("Failed to read data zone of ATECC508(%d)", ret);
			ret = AWS_E_CRYPTO_FAILURE;
			break;
		}
		if (!lockstate)	{
			AWS_ERROR("Un-Provisioned ATECC508");
			ret = AWS_E_CRYPTO_FAILURE;
			break;
		}

		ret = atcab_info(revision);
		if (ret != ATCA_SUCCESS) {
			AWS_ERROR("Failed to initialize ATECC508A!(%d)", ret);
			ret = AWS_E_CRYPTO_FAILURE;
			break;
		}

		ret = atcab_read_serial_number(kit->user.clientID);
		if (ret != ATCA_SUCCESS) {
			AWS_ERROR("Failed to read serial number of ATECC508A!(%d)", ret);
			ret = AWS_E_CRYPTO_FAILURE;
			break;
		}
		kit->user.clientIDLen = (uint32_t)ATCA_SERIAL_NUM_SIZE;

		ret = atca_tls_init_enc_key();
		if (ret != ATCA_SUCCESS) {
			AWS_ERROR("Failed to set parent key!(%d)", ret);
			ret = AWS_E_CRYPTO_FAILURE;
			break;
		}

		ret = nm_bsp_init();
		if (ret != M2M_SUCCESS) {
			AWS_ERROR("Failed to initialize Wireless module!(%d)", ret);
			ret = AWS_E_WIFI_INVALID;
			break;
		}

		kit->nonBlocking = false;

	} while(0);

	return ret;
}

int aws_main_build_certificate(t_aws_kit* kit)
{
	int ret = AWS_E_FAILURE;
	t_atcert cert;

	cert.signer_der = (uint8_t*)malloc(DER_CERT_INIT_SIZE);
	if (cert.signer_der == NULL) goto free_cert;
	cert.signer_der_size = DER_CERT_INIT_SIZE;
	cert.signer_pem = (uint8_t*)malloc(PEM_CERT_INIT_SIZE);
	if (cert.signer_pem == NULL) goto free_cert;
	cert.signer_pem_size = PEM_CERT_INIT_SIZE;
	cert.signer_pubkey= (uint8_t*)malloc(ATCERT_PUBKEY_SIZE);
	if (cert.signer_pubkey == NULL) goto free_cert;

	/* Build signer certificate */
	ret = atca_tls_build_signer_cert(&cert);
	if (ret != ATCA_SUCCESS) {
		ret = AWS_E_CRYPTO_CERT_FAILURE;
		AWS_ERROR("Failed to build signer certificate!(%d)", ret);
		goto free_cert; 
	}

	cert.device_der = (uint8_t*)malloc(DER_CERT_INIT_SIZE);
	if (cert.device_der == NULL) goto free_cert;
	cert.device_der_size = DER_CERT_INIT_SIZE;
	cert.device_pem = (uint8_t*)malloc(PEM_CERT_INIT_SIZE);
	if (cert.device_pem == NULL) goto free_cert;
	cert.device_pem_size = PEM_CERT_INIT_SIZE;
	cert.device_pubkey= (uint8_t*)malloc(ATCERT_PUBKEY_SIZE);
	if (cert.device_pubkey == NULL) goto free_cert;

	/* Build device certificate */
	ret = atca_tls_build_device_cert(&cert);
	if (ret != ATCA_SUCCESS) {
		ret = AWS_E_CRYPTO_CERT_FAILURE;
		AWS_ERROR("Failed to build device certificate!(%d)", ret);
		goto free_cert; 
	}

	kit->cert.signerCertLen = cert.signer_pem_size;
	memcpy(kit->cert.signerCert, cert.signer_pem, kit->cert.signerCertLen);
	kit->cert.devCertLen = cert.device_pem_size;
	memcpy(kit->cert.devCert, cert.device_pem, kit->cert.devCertLen);

free_cert:
	if (cert.signer_der) free(cert.signer_der);
	if (cert.signer_pem) free(cert.signer_pem);
	if (cert.signer_pubkey) free(cert.signer_pubkey);
	if (cert.device_der) free(cert.device_der);
	if (cert.device_pem) free(cert.device_pem);
	if (cert.device_pubkey) free(cert.device_pubkey);

	return ret;
}

int aws_main_reset_wifi_credential(t_aws_kit* kit)
{
	int ret = AWS_E_FAILURE;
	uint8_t userData[AWS_USER_DATA_OFFSET_HOST_LEN];

	memset(userData, 0x00, sizeof(userData));
	ret = atcab_write_bytes_zone(ATCA_ZONE_DATA, TLS_SLOT8_ENC_STORE, 0x00, userData, sizeof(userData));
	if (ret != ATCA_SUCCESS) {
		ret = AWS_E_CRYPTO_FAILURE;
	}

	return ret;
}

int aws_main_check_kit_state(t_aws_kit* kit)
{
	int ret = AWS_E_FAILURE;
	uint8_t userData[AWS_USER_DATA_OFFSET_MAX];

	do {

		memset(userData, 0x00, sizeof(userData));
		ret = atcab_read_bytes_zone(ATCA_ZONE_DATA, TLS_SLOT8_ENC_STORE, 0x00, userData, sizeof(userData));
		if (ret != ATCA_SUCCESS) {
			AWS_ERROR("Failed to get user data!(%d)", ret);
			ret = AWS_E_CRYPTO_FAILURE;
			break;
		}

		kit->user.ssidLen = AWS_GET_USER_DATA_LEN(userData, AWS_USER_DATA_OFFSET_SSID_LEN);
		kit->user.pskLen = AWS_GET_USER_DATA_LEN(userData, AWS_USER_DATA_OFFSET_PSK_LEN);
		kit->user.hostLen = AWS_GET_USER_DATA_LEN(userData, AWS_USER_DATA_OFFSET_HOST_LEN);
		kit->user.thingLen = AWS_GET_USER_DATA_LEN(userData, AWS_USER_DATA_OFFSET_THING_LEN);

		if (AWS_CHECK_USER_DATA_LEN(kit->user.ssidLen, AWS_WIFI_SSID_MAX) 
			|| AWS_CHECK_USER_DATA_LEN(kit->user.pskLen, AWS_WIFI_PSK_MAX)
			|| AWS_CHECK_USER_DATA_LEN(kit->user.hostLen, AWS_HOST_ADDR_MAX)
			|| AWS_CHECK_USER_DATA_LEN(kit->user.thingLen, AWS_THING_NAME_MAX)
			|| AWS_CHECK_USER_DATA(userData, AWS_USER_DATA_OFFSET_SSID)
			|| AWS_CHECK_USER_DATA(userData, AWS_USER_DATA_OFFSET_PSK)
			|| AWS_CHECK_USER_DATA(userData, AWS_USER_DATA_OFFSET_HOST)
			|| AWS_CHECK_USER_DATA(userData, AWS_USER_DATA_OFFSET_THING)) {
			ret = AWS_E_USER_DATA_INVALID;
			AWS_ERROR("Invalid user data, try to setup again!(%d)", ret);
			break;
		}

		memcpy(kit->user.ssid, &userData[AWS_USER_DATA_OFFSET_SSID], kit->user.ssidLen);
		memcpy(kit->user.psk, &userData[AWS_USER_DATA_OFFSET_PSK], kit->user.pskLen);
		memcpy(kit->user.host, &userData[AWS_USER_DATA_OFFSET_HOST], kit->user.hostLen);
		memcpy(kit->user.thing, &userData[AWS_USER_DATA_OFFSET_THING], kit->user.thingLen);

		ret = aws_net_init_wifi(kit, MAIN_WLAN_POLL_TIMEOUT_SEC);
		if (ret != AWS_E_SUCCESS) break;

		ret = aws_net_get_time(kit);
		if (ret != AWS_E_SUCCESS) {
			AWS_ERROR("Reset kit to reconnect to router to get correct Time info!(%d)", ret);
			aws_kit_software_reset();
			// Never come back here
		}

		ret = aws_main_build_certificate(kit);
		if (ret != AWS_E_SUCCESS) break;
#ifdef AWS_KIT_DEBUG
		AWS_INFO("SSID : %s, PWD : %s", kit->user.ssid, kit->user.psk);
#endif
		AWS_INFO("HOST : %s, THING : %s", kit->user.host, kit->user.thing);
	} while(0);

	return ret;
}

void aws_main_state_machine(t_aws_kit* kit)
{
	int ret = AWS_E_SUCCESS;
	static uint8_t currState = MAIN_STATE_INIT_KIT;
	uint8_t nextState = MAIN_STATE_INVALID;

	switch (currState)
	{
		case MAIN_STATE_INIT_KIT:
			ret = aws_main_init_kit(kit);
			if (ret == AWS_E_CRYPTO_FAILURE) {
				kit->errState = AWS_EX_UNPROVISIONED_CRYPTO;
				aws_user_exception_init_timer(kit);
				nextState = MAIN_STATE_PROVISIONING;
			} else {
				nextState = MAIN_STATE_CHECK_KIT;
			}
			break;

		case MAIN_STATE_CHECK_KIT:
			ret = aws_main_check_kit_state(kit);
			if (ret != AWS_E_SUCCESS) {
				kit->errState = AWS_EX_UNAVAILABLE_WIFI;
				aws_user_exception_init_timer(kit);
				nextState = MAIN_STATE_PROVISIONING;
			} else {
				kit->errState = AWS_EX_NONE;
				nextState = MAIN_STATE_RUN_KIT;
				vTaskResume(clientTaskHandler);
			}
			break;

		case MAIN_STATE_PROVISIONING:
			ret = aws_main_wait_notification(kit);
			if (ret != AWS_E_SUCCESS) {
				nextState = MAIN_STATE_PROVISIONING;
			} else {
				ret = aws_main_check_kit_state(kit);
				if (ret != AWS_E_SUCCESS) {
					nextState = MAIN_STATE_PROVISIONING;
				} else {
					kit->errState = AWS_EX_NONE;
					nextState = MAIN_STATE_RUN_KIT;
					vTaskResume(clientTaskHandler);
				}
			}
			break;

		case MAIN_STATE_RUN_KIT:
			ret = aws_main_wait_notification(kit);
			if (ret != AWS_E_SUCCESS) {
				nextState = MAIN_STATE_PROVISIONING;
			}
			nextState = MAIN_STATE_RUN_KIT;
			break;

		case MAIN_STATE_INVALID:
			nextState = MAIN_STATE_INVALID;
			break;

		default:
			break;
	}

	currState = kit->mainState = nextState;
}

void aws_main_task(void *params)
{
	t_aws_kit* kit = aws_kit_get_instance();
	kit->notiQueue = xQueueCreate(1, sizeof(uint8_t));
	
	for (;;) {

		aws_main_state_machine(kit);

		vTaskDelay(AWS_MAIN_TASK_DELAY);
	}
}

void aws_demo_tasks_init(void)
{

	xTaskCreate(aws_main_task,
			(const char *) "Main",
			AWS_MAIN_TASK_STACK_SIZE,
			NULL,
			AWS_MAIN_TASK_PRIORITY,
			&mainTaskHandler);

	xTaskCreate(aws_prov_task,
			(const char *) "Prov",
			AWS_PROV_TASK_STACK_SIZE,
			NULL,
			AWS_PROV_TASK_PRIORITY,
			&provTaskHandler);

	xTaskCreate(aws_user_task,
			(const char *) "User",
			AWS_USER_TASK_STACK_SIZE,
			NULL,
			AWS_USER_TASK_PRIORITY,
			&userTaskHandler);

	xTaskCreate(aws_client_task,
			(const char *) "Client",
			AWS_CLIENT_TASK_STACK_SIZE,
			NULL,
			AWS_CLIENT_TASK_PRIORITY,
			&clientTaskHandler);

	vTaskSuspend(clientTaskHandler);

}

