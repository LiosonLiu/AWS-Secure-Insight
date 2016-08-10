/**
 * \brief  Atmel Crypto Auth hardware interface object
 *
 * Copyright (c) 2015 Atmel Corporation. All rights reserved.
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
 */

#include <ctype.h>
#include <string.h>
#include "conf_usb.h"
#include "cryptoauthlib.h"
#include "tls/atcatls_cfg.h"
#include "aws_prov_task.h"
#include "aws_kit_object.h"
#include "cert_def_1_signer.h"
#include "cert_def_2_device.h"

/** \brief version of development kit firmware
 *         that contains AES132 and SHA204 library */
const char VersionKit[] = {1, 0, 5};
const char VersionSha204[] = {1, 3, 0};
const char VersionAes132[] = {1, 1, 0};
const char VersionEcc508[] = {1, 1, 0};		//!< ECC108 string

const char StringSha204[] = "SHA204 ";		//!< SHA204 string
const char StringAes132[] = "AES132 ";		//!< AES132 string
const char StringEcc508[] = "ECC108 ";		//!< ECC108 string

const char StringKitShort[] = "CK590 ";		//!< short string of Microbase kit
const char StringKit[] = "ATSAMG55 ";		//!< long string of Microbase kit

device_info_t device_info[DISCOVER_DEVICE_COUNT_MAX];
uint8_t device_count = 0;

static uint8_t pucUsbRxBuffer[USB_BUFFER_SIZE_RX];
static uint8_t pucUsbTxBuffer[USB_BUFFER_SIZE_TX];
static uint8_t rxPacketStatus = KIT_STATUS_SUCCESS;
static uint16_t rxBufferIndex = 0;

/** \brief This function returns the rx buffer.
 *  \return pointer to the current rx buffer index
 */
uint8_t* aws_prov_get_rx_buffer(void)
{
	return pucUsbRxBuffer;
}

uint8_t* aws_prov_get_tx_buffer(void)
{
	return pucUsbTxBuffer;
}

/** \brief This function converts a nibble to Hex-ASCII.
 * \param[in] nibble nibble value to be converted
 * \return ASCII value
**/
uint8_t aws_prov_convert_nibble_to_ascii(uint8_t nibble)
{
    nibble &= 0x0F;
    if (nibble <= 0x09 )
        nibble += '0';
    else
        nibble += ('A' - 10);
    return nibble;
}

/** \brief This function converts an ASCII character to a nibble.
 * \param[in] ascii ASCII value to be converted
 * \return nibble value
**/
uint8_t aws_prov_convert_ascii_to_nibble(uint8_t ascii)
{
    if ((ascii <= '9') && (ascii >= '0'))
        ascii -= '0';
    else if ((ascii <= 'F' ) && (ascii >= 'A'))
        ascii -= ('A' - 10);
    else if ((ascii <= 'f') && (ascii >= 'a'))
        ascii -= ('a' - 10);
    else
        ascii = 0;
    return ascii;
}

/** \brief This function converts ASCII to binary.
 * \param[in] length number of bytes in buffer
 * \param[in, out] buffer pointer to buffer
 * \return number of bytes in buffer
 */
uint16_t aws_prov_convert_ascii_to_binary(uint16_t length, uint8_t *buffer)
{
	if (length < 2)
		return 0;

	uint16_t i, binIndex;

	for (i = 0, binIndex = 0; i < length; i += 2)
	{
		buffer[binIndex] = aws_prov_convert_ascii_to_nibble(buffer[i]) << 4;
		buffer[binIndex++] |= aws_prov_convert_ascii_to_nibble(buffer[i + 1]);
	}

	return binIndex;
}

device_info_t* aws_prov_get_device_info(uint8_t index) 
{
	if (index >= device_count)
		return NULL;
	return &device_info[index];
}

device_type_t aws_prov_get_device_type(uint8_t index) 
{
	if (index >= device_count)
		return DEVICE_TYPE_UNKNOWN;
	return device_info[index].device_type;
}

ATCA_STATUS aws_prov_detect_I2c_devices()
{
	ATCA_STATUS status = ATCA_NO_DEVICES;
	uint8_t revision[4] = { 0 };

	cfg_ateccx08a_i2c_default.atcai2c.slave_address = DEVICE_I2C;
	status = atcab_init( &cfg_ateccx08a_i2c_default );
	if (status != ATCA_SUCCESS) RETURN(status, "Failed: Initialize interface");

	// Test the init
	status = atcab_info(revision);
	if (status != ATCA_SUCCESS) {
		atcab_release();
		// Failed to communicate, try the DEVICE_I2C address
		cfg_ateccx08a_i2c_default.atcai2c.slave_address = FACTORY_INIT_I2C;
		status = atcab_init( &cfg_ateccx08a_i2c_default );
		if (status != ATCA_SUCCESS) return status;
		// Test the init
		status = atcab_info(revision);
		if (status != ATCA_SUCCESS) RETURN(status, "Failed: Not connected to ECC508");
	}

	device_info[device_count].address = cfg_ateccx08a_i2c_default.atcai2c.slave_address;
	device_info[device_count].bus_type = DEVKIT_IF_I2C;
	device_info[device_count].device_type = DEVICE_TYPE_ECC108;
	memcpy(device_info[device_count].dev_rev, revision, sizeof(revision));

	device_count++;
	
	return status;
}

/** \brief This function tries to find SHA204 and / or AES132 devices.
 *
 *         It calls functions for all three interfaces,
 *         SWI, I2C, and SPI. They in turn enter found
 *         devices into the #device_info array.
 * \return interface found
 */
interface_id_t aws_prov_discover_devices()
{
	ATCA_STATUS status = ATCA_NO_DEVICES;
	interface_id_t bus_type;

	device_count = 0;
	memset(device_info, 0, sizeof(device_info));

	status = aws_prov_detect_I2c_devices();

	if (device_count == 0 || status != ATCA_SUCCESS)
		return DEVKIT_IF_UNKNOWN;

	bus_type = device_info[0].bus_type;

	return bus_type;
}

/** \brief This function parses kit commands (ASCII) received from a
 * 			PC host and returns an ASCII response.
 * \param[in] commandLength number of bytes in command buffer
 * \param[in] command pointer to ASCII command buffer
 * \param[out] responseLength pointer to number of bytes in response buffer
 * \param[out] response pointer to binary response buffer
 * \param[out] responseIsAscii pointer to response type
 * \return the status of the operation
 */
uint8_t aws_prov_parse_board_commands(uint16_t commandLength, uint8_t *command, 
										uint16_t *responseLength, uint8_t *response, uint8_t *responseIsAscii)
{
	uint8_t status = KIT_STATUS_UNKNOWN_COMMAND;
	uint16_t responseIndex = 0;
	uint16_t deviceIndex;
	uint16_t dataLength = 1;
	uint8_t *rxData[1];
	interface_id_t device_interface = DEVKIT_IF_UNKNOWN;
	device_info_t* dev_info;
	const char *StringInterface[] = {"no_device ", "SPI ", "TWI ", "SWI "};
	const char *pToken = strchr((char *) command, ':');

	if (!pToken)
		return status;

	*responseIsAscii = 1;

	switch(pToken[1]) {

		case 'v':
			// Gets abbreviated board name and, if found, first device type and interface type.
			// response (no device): <kit version>, "no_devices"<status>()
			// response (device found): <kit version>, <device type>, <interface><status>(<address>)			
			break;
		
		case 'f':
			status = aws_prov_extract_data_load((const char*)pToken, &dataLength, rxData);
			if (status != KIT_STATUS_SUCCESS)
				break;

			dataLength = 4; // size of versions + status byte

			switch (*rxData[0]) {
				case 0: // kit version
					strcpy((char *) response, StringKit);
					responseIndex = strlen((char *) response);
					memcpy((char *) (response + responseIndex + 1), VersionKit, dataLength);
					break;

				case 1: // SHA204 library version
					strcpy((char *) response, StringSha204);
					responseIndex = strlen((char *) response);
					memcpy((char *) (response + responseIndex + 1), VersionSha204, dataLength);
					break;

				case 2: // AES132 library version
					strcpy((char *) response, StringAes132);
					responseIndex = strlen((char *) response);
					memcpy((char *) (response + responseIndex + 1), VersionAes132, dataLength);
					break;

				case 3: // ECC508 library version
					strcpy((char *) response, StringEcc508);
					responseIndex = strlen((char *) response);
					memcpy((char *) (response + responseIndex + 1), VersionEcc508, dataLength);
					break;

				default:
					status = KIT_STATUS_INVALID_PARAMS;
					break;
			}
			break;

		case 'd':
			status = aws_prov_extract_data_load((const char*)pToken, &dataLength, rxData);
			if (status != KIT_STATUS_SUCCESS)
				break;

			device_interface = aws_prov_discover_devices();
			deviceIndex = *rxData[0];
			dev_info = aws_prov_get_device_info(deviceIndex);
			if (!dev_info) {
				status = KIT_STATUS_NO_DEVICE;
				break;
			}

			switch (dev_info->device_type) {
				case DEVICE_TYPE_SHA204:
					strcpy((char *) response, StringSha204);
					break;

				case DEVICE_TYPE_AES132:
					strcpy((char *) response, StringAes132);
					break;

				case DEVICE_TYPE_ECC108:
					strcpy((char *) response, StringEcc508);
					break;

				case DEVICE_TYPE_UNKNOWN:
					strcpy((char *) response, StringInterface[0]);
					status = KIT_STATUS_NO_DEVICE;
					break;

				default:
					strcpy((char *) response, "unknown_device");
					break;
			}


			if (dev_info->bus_type == DEVKIT_IF_UNKNOWN) {
				responseIndex = strlen((char *) response);
				break;
			}
			
			// Append interface type to response.
			strcat((char*)response, StringInterface[device_interface]);
			responseIndex = strlen((char *) response);

			// Append the address (TWI) / index (SWI) of the device.
			// Skip one byte for status.
			dataLength++;
			response[responseIndex + 1] = dev_info->bus_type == DEVKIT_IF_I2C ? dev_info->address : dev_info->device_index;
			break;

		default:
			status = KIT_STATUS_UNKNOWN_COMMAND;
			break;
			
	}
	
	// Append <status>(<data>).
	response[responseIndex] = status;
	*responseLength = aws_prov_create_usb_packet(dataLength, &response[responseIndex]) + responseIndex;
	
	return status;
}

/** \brief Give index of command and response length based on received command.  
 * \param[in] tx_buffer includes command to be sent to device 
 * \param[out] cmd_index is index corresponding to opcode
 * \param[out] rx_length is length of response to be came to device
 * \return ATCA_SUCCESS
 */
uint8_t aws_prov_get_commands_info(uint8_t *tx_buffer, uint8_t *cmd_index, uint16_t *rx_length)
{
	uint8_t status = ATCA_SUCCESS;
	uint8_t opCode = tx_buffer[1];
	uint8_t param1 = tx_buffer[2];
	
	switch (opCode) {
		
		case ATCA_CHECKMAC:
			*cmd_index = CMD_CHECKMAC;
			*rx_length = CHECKMAC_RSP_SIZE;
			break;
		
		case ATCA_COUNTER:
			*cmd_index = CMD_COUNTER;
			*rx_length = COUNTER_RSP_SIZE;
			break;
		
		case ATCA_DERIVE_KEY:
			*cmd_index = CMD_DERIVEKEY;
			*rx_length = DERIVE_KEY_RSP_SIZE;
			break;
		
		case ATCA_ECDH:
			*cmd_index = CMD_ECDH;
			*rx_length = ECDH_RSP_SIZE;
			break;
		
		case ATCA_GENDIG:
			*cmd_index = CMD_GENDIG;
			*rx_length = GENDIG_RSP_SIZE;
			break;
		
		case ATCA_GENKEY:
			*cmd_index = CMD_GENKEY;
			*rx_length = (param1 == GENKEY_MODE_DIGEST)	? GENKEY_RSP_SIZE_SHORT : GENKEY_RSP_SIZE_LONG;
			break;
		
		case ATCA_HMAC:
			*cmd_index = CMD_HMAC;
			*rx_length = HMAC_RSP_SIZE;
			break;
		
		case ATCA_INFO:
			*cmd_index = CMD_INFO;
			*rx_length = INFO_RSP_SIZE;
			break;

		case ATCA_LOCK:
			*cmd_index = CMD_LOCK;
			*rx_length = LOCK_RSP_SIZE;
			break;
		
		case ATCA_MAC:
			*cmd_index = CMD_MAC;
			*rx_length = MAC_RSP_SIZE;
			break;
		
		case ATCA_NONCE:
			*cmd_index = CMD_NONCE;
			*rx_length = (param1 == NONCE_MODE_PASSTHROUGH)	? NONCE_RSP_SIZE_SHORT : NONCE_RSP_SIZE_LONG;
			break;
		
		case ATCA_PAUSE:
			*cmd_index = CMD_PAUSE;
			*rx_length = PAUSE_RSP_SIZE;
			break;
		
		case ATCA_PRIVWRITE:
			*cmd_index = CMD_PRIVWRITE;
			*rx_length = PRIVWRITE_RSP_SIZE;
			break;
		
		case ATCA_RANDOM:
			*cmd_index = CMD_RANDOM;
			*rx_length = RANDOM_RSP_SIZE;
			break;
		
		case ATCA_READ:
			*cmd_index = CMD_READMEM;
			*rx_length = (param1 & 0x80)	? READ_32_RSP_SIZE : READ_4_RSP_SIZE;
			break;
		
		case ATCA_SHA:
			*cmd_index = CMD_SHA;
			*rx_length = (param1 == SHA_MODE_SHA256_END) ? ATCA_RSP_SIZE_32 : ATCA_RSP_SIZE_4;
			break;

		case ATCA_SIGN:
			*cmd_index = CMD_SIGN;
			*rx_length = SIGN_RSP_SIZE;
			break;
		
		case ATCA_UPDATE_EXTRA:
			*cmd_index = CMD_UPDATEEXTRA;
			*rx_length = UPDATE_RSP_SIZE;
			break;
		
		case ATCA_VERIFY:
			*cmd_index = CMD_VERIFY;
			*rx_length = VERIFY_RSP_SIZE;
			break;
		
		case ATCA_WRITE:
			*cmd_index = CMD_WRITEMEM;
			*rx_length = WRITE_RSP_SIZE;
			break;
		
		default:
			break;
		
	}

	return status;
}

/** \brief Actually send a command array and receive a result from device.  
 * \param[in] tx_buffer is buffer to be sent
 * \param[in] rx_buffer is buffer to be received
 * \return ATCA_STATUS
 */
uint8_t aws_prov_send_and_receive(uint8_t *tx_buffer, uint8_t *rx_buffer)
{
	uint8_t status = ATCA_SUCCESS;
	uint8_t cmd_index;
	uint16_t rx_length;
	uint16_t execution_time = 0;
	uint8_t *cmd_buffer;
	ATCADevice  _gDevice = NULL;
	ATCACommand _gCommandObj = NULL;
	ATCAIface   _gIface = NULL;

	do {

		if ( tx_buffer == NULL || rx_buffer == NULL )
			break;

		if ( aws_prov_get_commands_info( tx_buffer, &cmd_index, &rx_length ) != ATCA_SUCCESS )
			break;

		cmd_buffer = (uint8_t *)malloc(tx_buffer[0] + 1);
		memcpy(&cmd_buffer[1], tx_buffer, tx_buffer[0]);
		
		_gDevice= atcab_getDevice();
		_gCommandObj = atGetCommands(_gDevice);
		_gIface = atGetIFace(_gDevice);

		execution_time = atGetExecTime( _gCommandObj, cmd_index);

		if ( (status = atcab_wakeup()) != ATCA_SUCCESS )
			break;
	
		// send the command
		if ((status = atsend( _gIface, (uint8_t *)cmd_buffer, tx_buffer[0])) != ATCA_SUCCESS )
			break;

		// delay the appropriate amount of time for command to execute
		atca_delay_ms(execution_time);

		// receive the response
		if ((status = atreceive( _gIface, rx_buffer, &rx_length)) != ATCA_SUCCESS )
			break;

		atcab_idle();

		free((void *)cmd_buffer);

	} while(0);
	
	return status;
	
}

/** \brief Only send a command array.
 * \param[in] tx_buffer is buffer to be sent
 * \return ATCA_STATUS
 */
uint8_t aws_prov_send_command(uint8_t *tx_buffer)
{
	uint8_t status = ATCA_SUCCESS;
	uint8_t cmd_index;
	uint16_t rx_length;
	uint16_t execution_time = 0;
	uint8_t *cmd_buffer;
	ATCADevice  _gDevice = NULL;
	ATCACommand _gCommandObj = NULL;
	ATCAIface   _gIface = NULL;

	do {

		if ( tx_buffer == NULL )
			break;

		if ( aws_prov_get_commands_info( tx_buffer, &cmd_index, &rx_length ) != ATCA_SUCCESS )
			break;

		cmd_buffer = (uint8_t *)malloc(tx_buffer[0] + 1);
		memcpy(&cmd_buffer[1], tx_buffer, tx_buffer[0]);

		_gDevice= atcab_getDevice();
		_gCommandObj = atGetCommands(_gDevice);
		_gIface = atGetIFace(_gDevice);
		
		execution_time = atGetExecTime( _gCommandObj, cmd_index);

		if ( (status = atcab_wakeup()) != ATCA_SUCCESS )
			break;
		
		// send the command
		if ( (status = atsend( _gIface, (uint8_t *)cmd_buffer, tx_buffer[0])) != ATCA_SUCCESS )
			break;

		// delay the appropriate amount of time for command to execute
		atca_delay_ms(execution_time);

		atcab_idle();

		free((void *)cmd_buffer);

	} while(0);
	
	return status;
	
}

/** \brief Only receive a command array.
 * \param[in] size is size to be received
 * \param[out] rx_buffer is buffer that includes data to be received from a device 
 * \return ATCA_STATUS
 */
uint8_t aws_prov_receive_response(uint8_t size, uint8_t *rx_buffer)
{
	uint8_t status = ATCA_SUCCESS;
	uint16_t rxlength = size;	
	ATCADevice  _gDevice = NULL;
	ATCAIface   _gIface = NULL;

	do {

		if ( rx_buffer == NULL )
			break;

		_gDevice= atcab_getDevice();
		
		if ( (status = atcab_wakeup()) != ATCA_SUCCESS )
			break;

		_gDevice= atcab_getDevice();
		_gIface = atGetIFace(_gDevice);

		// receive the response
		if ( (status = atreceive( _gIface, rx_buffer, &rxlength)) != ATCA_SUCCESS )
			break;

		atcab_idle();

	} while(0);
	
	return status;
	
}

/** \brief This function parses communication commands (ASCII) received from a
 *         PC host and returns a binary response.
 *
 *         protocol syntax:\n\n
 *         functions for command sequences:\n
 *            v[erify]                            several Communication and Command Marshaling layer functions
 *            a[tomic]                            Wraps "talk" into a Wakeup / Idle.
 *         functions in sha204_comm.c (Communication layer):\n
 *            w[akeup]                            sha204c_wakeup\n
 *            t[alk](command)                     sha204c_send_and_receive\n
 *         functions in sha204_i2c.c / sha204_swi.c (Physical layer):\n
 *            [physical:]s[leep]                  sha204p_sleep\n
 *            [physical:]i[dle]                   sha204p_idle\n
 *            p[hysical]:r[esync]                 sha204p_resync\n
 *            p[hysical]:e[nable]                 sha204p_init\n
 *            p[hysical]:d[isable]                sha204p_disable_interface\n
 *            c[ommand](data)                     sha204p_send_command\n
 *            r[esponse](size)                    sha204p_receive_response\n
 * \param[in] commandLength number of bytes in command buffer
 * \param[in] command pointer to ASCII command buffer
 * \param[out] responseLength pointer to number of bytes in response buffer
 * \param[out] response pointer to binary response buffer
 * \return the status of the operation
 */
uint8_t aws_prov_parse_ecc_commands(uint16_t commandLength, uint8_t *command, uint16_t *responseLength, uint8_t *response)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	uint16_t dataLength;
	uint8_t *data_load[1];
	uint8_t *dataLoad;
	char *pToken = strchr((char *) command, ':');

	*responseLength = 0;

	if (!pToken)
		return status;

	switch (pToken[1]) {
		// Talk (send command and receive response)		
		case 't':
			status = aws_prov_extract_data_load((const char*)pToken + 2, &dataLength, data_load);
			if (status != KIT_STATUS_SUCCESS)
				return status;

			response[SHA204_BUFFER_POS_COUNT] = 0;
			status = aws_prov_send_and_receive(data_load[0], &response[0]);
			if (status != KIT_STATUS_SUCCESS)
				return status;

			*responseLength = response[SHA204_BUFFER_POS_COUNT];
			break;

		// Wakeup
		case 'w':
			status = atcab_wakeup();
			if (status != KIT_STATUS_SUCCESS)
				return status;
			break;

		// Sleep
		case 's':
			status = atcab_sleep();
			if (status != KIT_STATUS_SUCCESS)
				return status;
			break;

		// Idle
		case 'i':
			status = atcab_idle();
			if (status != KIT_STATUS_SUCCESS)
				return status;			
			break;
		
		// Switch whether to wrap a Wakeup / Idle around a "talk" message.
		case 'a':
			status = aws_prov_extract_data_load((const char*)pToken + 2, &dataLength, data_load);
			if (status != KIT_STATUS_SUCCESS)
				return status;
			break;

		// --------- calls functions in sha204_i2c.c and sha204_swi.c  ------------------
		case 'p':
			// ----------------------- "s[ha204]:p[hysical]:" ---------------------------
			pToken = strchr(&pToken[1], ':');
			if (!pToken)
				return status;

			switch (pToken[1]) {
				// Wake-up without receive.
				case 'w':
					status = atcab_wakeup();
					if (status != KIT_STATUS_SUCCESS)
						return status;					
					break;

				case 'c':
					// Send command.
					status = aws_prov_extract_data_load((const char*)pToken + 2, &dataLength, data_load);
					if (status != KIT_STATUS_SUCCESS)
						return status;
					dataLoad = data_load[0];
					status = aws_prov_send_command(dataLoad);				
					break;

				// Receive response.
				case 'r':
					status = aws_prov_extract_data_load((const char*)pToken + 2, &dataLength, data_load);
					if (status != KIT_STATUS_SUCCESS)
						return status;
					// Reset count byte.
					response[SHA204_BUFFER_POS_COUNT] = 0;
					status = aws_prov_receive_response(*data_load[0], response);
					if (status != KIT_STATUS_SUCCESS)
						return status;					
					*responseLength = response[SHA204_BUFFER_POS_COUNT];
					break;

				case 's':
					// -- "s[elect](device index | TWI address)" or "s[leep]" ----------------
					status = aws_prov_extract_data_load((const char*)pToken + 2, &dataLength, data_load);
					if (status == KIT_STATUS_SUCCESS) {
						// Select device (I2C: address; SWI: index into GPIO array).
						dataLoad = data_load[0];
					} else {
						// Sleep command
						status = atcab_idle();
						if (status != KIT_STATUS_SUCCESS)
							return status;						
					}
					break;

				default:
					status = KIT_STATUS_UNKNOWN_COMMAND;
					break;
					
				} // end physical			
			break;
			
		default:
			status = KIT_STATUS_UNKNOWN_COMMAND;
			break;
	}
	
	return status;
}

/** \brief This function extracts data from a command string and
 * 			converts them to binary.
 *
 * The data load is expected to be in Hex-Ascii and surrounded by parentheses.
 * \param[in] command command string
 * \param[out] dataLength number of bytes extracted
 * \param[out] data pointer to pointer to binary data
 * \return status: invalid parameters or success
 */
uint8_t aws_prov_extract_data_load(const char* command, uint16_t* dataLength, uint8_t** data)
{
	uint8_t status = KIT_STATUS_INVALID_PARAMS;
	if (!command || !dataLength || !data)
		return status;

	char* pToken = strchr(command, '(');
	if (!pToken)
		return status;

	char* dataEnd = strchr(pToken, ')');
	if (!dataEnd)
		// Allow a missing closing parenthesis.
		dataEnd = (char *) command + strlen(command);
	else
		dataEnd--;

	uint16_t asciiLength = (uint16_t) (dataEnd - pToken);
	*data = (uint8_t *) pToken + 1;
	*dataLength = aws_prov_convert_ascii_to_binary(asciiLength, *data);

	return KIT_STATUS_SUCCESS;
}

uint8_t aws_prov_extract_data_load_tokens(const char *command, uint16_t *dataLength, uint8_t **data, uint8_t start_token, uint8_t end_token)
{
	uint8_t status = KIT_STATUS_INVALID_PARAMS;
	if (!command || !dataLength || !data)
	return status;

	char *pToken = strchr(command, start_token);
	if (!pToken)
	return status;

	char *dataEnd = strchr(pToken, end_token);
	if (!dataEnd)
	// Allow a missing closing parenthesis.
	dataEnd = (char *) command + strlen(command);
	else
	dataEnd--;

	uint16_t asciiLength = (uint16_t) (dataEnd - pToken);
	*data = (uint8_t *) pToken + 1;
	*dataLength = aws_prov_convert_ascii_to_binary(asciiLength, *data);
	return KIT_STATUS_SUCCESS;
}

/** \brief This function converts binary response data to hex-ascii and packs it into a protocol response.
           <status byte> <'('> <hex-ascii data> <')'> <'\n'>
    \param[in] length number of bytes in data load plus one status byte
    \param[in] buffer pointer to data
    \return length of ASCII data
*/
uint16_t aws_prov_create_usb_packet(uint16_t length, uint8_t *buffer)
{
	uint16_t binBufferIndex = length - 1;
	// Size of data load is length minus status byte.
	uint16_t asciiLength = 2 * (length - 1) + 5; // + 5: 2 status byte characters + '(' + ")\n"
	uint16_t asciiBufferIndex = asciiLength - 1;
	uint8_t byteValue;

	// Terminate ASCII packet.
	buffer[asciiBufferIndex--] = KIT_EOP;

	// Append ')'.
	buffer[asciiBufferIndex--] = ')';

	// Convert binary data to hex-ascii starting with the last byte of data.
	while (binBufferIndex)
	{
		byteValue = buffer[binBufferIndex--];
		buffer[asciiBufferIndex--] = aws_prov_convert_nibble_to_ascii(byteValue);
		buffer[asciiBufferIndex--] = aws_prov_convert_nibble_to_ascii(byteValue >> 4);
	}

	// Start data load with open parenthesis.
	buffer[asciiBufferIndex--] = '(';

	// Convert first byte (function return value) to hex-ascii.
	byteValue = buffer[0];
	buffer[asciiBufferIndex--] = aws_prov_convert_nibble_to_ascii(byteValue);
	buffer[asciiBufferIndex] = aws_prov_convert_nibble_to_ascii(byteValue >> 4);

	return asciiLength;
}

/** \brief This function converts binary data to Hex-ASCII.
 * \param[in] length number of bytes to send
 * \param[in] buffer pointer to tx buffer
 * \return new length of data
 */
uint16_t aws_prov_convert_data(uint16_t length, uint8_t *buffer)
{
	if (length > DEVICE_BUFFER_SIZE_MAX_RX) {
		buffer[0] = KIT_STATUS_USB_TX_OVERFLOW;
		length = DEVICE_BUFFER_SIZE_MAX_RX;
	}
	return aws_prov_create_usb_packet(length, buffer);
}

/** \brief Interpret Rx packet, and then execute received command.  
 * \param[in] rx_length is length of received packet 
 * \param[in] txLength is Tx length to be sent to Host
 * returns pointer of buffer to be sent
 */
uint8_t* aws_prov_process_usb_packet(uint16_t rx_length, uint16_t *txLength)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	uint8_t responseIsAscii = 0;
	uint16_t rxLength = rx_length - 1;	// except for a line feed character
	uint8_t* txBuffer = aws_prov_get_tx_buffer();
	uint8_t* pRxBuffer = aws_prov_get_rx_buffer();

	if (rxPacketStatus != KIT_STATUS_SUCCESS) {
		pucUsbTxBuffer[0] = rxPacketStatus;
		*txLength = 1;
		*txLength = aws_prov_convert_data(*txLength, pucUsbTxBuffer);
	}
	
	if (pRxBuffer[0] == 'l') {	// lib
		// "lib" as the first field is optional. Move rx pointer to the next field.
		pRxBuffer = memchr(pRxBuffer, ':', rxBufferIndex);
		if (!pRxBuffer)
			status = KIT_STATUS_UNKNOWN_COMMAND;
		else
			pRxBuffer++;
	}
		
	switch (pRxBuffer[0]) {
			
		case 's':
		case 'e':			
			status = aws_prov_parse_ecc_commands(rxLength, (uint8_t *)pRxBuffer, txLength, pucUsbTxBuffer + 1);
			break;

		case 'B':
		case 'b':
			// board level commands ("b[oard]")
			status = aws_prov_parse_board_commands((uint8_t) rxLength, (uint8_t *)pRxBuffer, txLength, txBuffer, &responseIsAscii);
			break;

		case 'A':
		case 'a':
				switch (pRxBuffer[1])
				{
					case 'W':
					case 'w':
						status = aws_prov_parse_aws_commands(rxLength, (uint8_t *) pRxBuffer, txLength, pucUsbTxBuffer + 1);
					break;
					default:
					break;
				}
		break;
		default:
			status = KIT_STATUS_UNKNOWN_COMMAND;
			*txLength = 1;			
			break;
	}

	if (!responseIsAscii) {
		// Copy leading function return byte.
		pucUsbTxBuffer[0] = status;
		// Tell aws_prov_convert_data the correct txLength.
		if (*txLength < DEVICE_BUFFER_SIZE_MAX_RX)
			(*txLength)++;
		*txLength = aws_prov_convert_data(*txLength, pucUsbTxBuffer);
	}
	
	return txBuffer;
}

uint8_t aws_prov_save_signer_public_key(uint8_t *public_key)
{
	uint8_t ret = ATCA_SUCCESS;
	size_t end_block = 3, start_block = 0;
	uint8_t padded_public_key[96];

	memset(padded_public_key, 0x00, sizeof(padded_public_key));
	memmove(&padded_public_key[40], &public_key[32], 32);
	memset(&padded_public_key[36], 0, 4);
	memmove(&padded_public_key[4], &public_key[0], 32);
	memset(&padded_public_key[0], 0, 4);

	for (; start_block < end_block; start_block++) {
		ret = atcab_write_zone(DEVZONE_DATA, TLS_SLOT_SIGNER_PUBKEY, 
							start_block, 0, &padded_public_key[(start_block - 0) * 32], 32);
		if (ret != ATCA_SUCCESS) return ret;
	}

	return ret;
}

uint8_t aws_prov_get_signer_public_key(uint8_t *public_key)
{
	uint8_t ret = ATCA_SUCCESS;
	size_t end_block = 3, start_block = 0;
	uint8_t padded_public_key[96];

	memset(padded_public_key, 0x00, sizeof(padded_public_key));
	for (; start_block < end_block; start_block++) {
		ret = atcab_read_zone(DEVZONE_DATA, TLS_SLOT_SIGNER_PUBKEY, 
							start_block, 0, &padded_public_key[(start_block - 0) * 32], 32);
		if (ret != ATCA_SUCCESS) return ret;
	}

	memcpy(&public_key[32], &padded_public_key[40], 32);
	memcpy(&public_key[0], &padded_public_key[4], 32);

	return ret;
}

uint8_t aws_prov_build_tbs_cert_digest(
	const atcacert_def_t*    cert_def,
	uint8_t*                 cert,
	size_t*                  cert_size,
	const uint8_t            ca_public_key[64],
	const uint8_t            public_key[64],
	const uint8_t            signer_id[2],
	const atcacert_tm_utc_t* issue_date,
	const uint8_t            config32[32],
	uint8_t*                 tbs_digest)
{
	int ret = ATCACERT_E_SUCCESS;
	atcacert_build_state_t build_state;
	atcacert_tm_utc_t expire_date = {
		.tm_year = issue_date->tm_year + cert_def->expire_years,
		.tm_mon = issue_date->tm_mon,
		.tm_mday = issue_date->tm_mday,
		.tm_hour = issue_date->tm_hour,
		.tm_min = 0,
		.tm_sec = 0
	};
	const atcacert_device_loc_t config32_dev_loc = {
		.zone = DEVZONE_CONFIG,
		.offset = 0,
		.count = 32
	};

	if (cert_def->expire_years == 0)
	{
		ret = atcacert_date_get_max_date(cert_def->expire_date_format, &expire_date);
		if (ret != ATCACERT_E_SUCCESS) return ret;
	}

	ret = atcacert_cert_build_start(&build_state, cert_def, cert, cert_size, ca_public_key);
	if (ret != ATCACERT_E_SUCCESS) return ret;

	ret = atcacert_set_subj_public_key(build_state.cert_def, build_state.cert, *build_state.cert_size, public_key);
	if (ret != ATCACERT_E_SUCCESS) return ret;
	ret = atcacert_set_issue_date(build_state.cert_def, build_state.cert, *build_state.cert_size, issue_date);
	if (ret != ATCACERT_E_SUCCESS) return ret;
	ret = atcacert_set_expire_date(build_state.cert_def, build_state.cert, *build_state.cert_size, &expire_date);
	if (ret != ATCACERT_E_SUCCESS) return ret;
	ret = atcacert_set_signer_id(build_state.cert_def, build_state.cert, *build_state.cert_size, signer_id);
	if (ret != ATCACERT_E_SUCCESS) return ret;
	ret = atcacert_cert_build_process(&build_state, &config32_dev_loc, config32);
	if (ret != ATCACERT_E_SUCCESS) return ret;

	ret = atcacert_cert_build_finish(&build_state);
	if (ret != ATCACERT_E_SUCCESS) return ret;

	ret = atcacert_get_tbs_digest(build_state.cert_def, build_state.cert, *build_state.cert_size, tbs_digest);
	if (ret != ATCACERT_E_SUCCESS) return ret;

	return ret;
}

uint8_t aws_prov_build_and_save_cert(uint8_t* signature, uint8_t cert_id)
{
	uint8_t ret = ATCA_SUCCESS;
	uint8_t cert[AWS_CERT_LENGH_MAX] = {0}, tbs_digest[ATCA_SHA_DIGEST_SIZE];
	const atcacert_def_t* cert_def = (cert_id == AWS_SIGNER_CERT_ID) ? &g_cert_def_1_signer : &g_cert_def_2_device;
	size_t cert_size = sizeof(cert);
	size_t max_cert_size = cert_size;
	uint8_t pub_key[ATCA_PUB_KEY_SIZE] = { 0 };
	uint8_t signer_pub_key[ATCA_PUB_KEY_SIZE] = { 0 };
	uint8_t signer_id[2] = {0x00, 0x00};
	uint8_t configdata[ATCA_CONFIG_SIZE];
	atcacert_device_loc_t device_locs[4];
	size_t device_locs_count = 0;
	size_t i;
	const atcacert_tm_utc_t issue_date = {
		.tm_year = 2016 - 1900,
		.tm_mon  = 7 - 1,
		.tm_mday = 19,
		.tm_hour = 20,
		.tm_min  = 0,
		.tm_sec  = 0
	};
	
	do {
			
		ret = atcab_read_config_zone(configdata);
		if (ret != ATCA_SUCCESS) break;
		
		ret = atcab_get_pubkey(TLS_SLOT_AUTH_PRIV, pub_key);
		if (ret != ATCA_SUCCESS) break;

		ret = aws_prov_get_signer_public_key(signer_pub_key);
		if (ret != ATCA_SUCCESS) break;

		ret = aws_prov_build_tbs_cert_digest(cert_def, cert, &cert_size, signer_pub_key, 
				pub_key, signer_id, &issue_date, configdata, tbs_digest);
		if (ret != ATCACERT_E_SUCCESS) break;

		ret = atcacert_set_signature(cert_def, cert, &cert_size, max_cert_size, signature);
		if (ret != ATCACERT_E_SUCCESS) return ret;

		ret = atcacert_get_device_locs(cert_def, device_locs, &device_locs_count, sizeof(device_locs) / sizeof(device_locs[0]), 32);
		if (ret != ATCACERT_E_SUCCESS) return ret;

		for (i = 0; i < device_locs_count; i++)	{

			size_t end_block, start_block, block;
			uint8_t data[96];

			if (device_locs[i].zone == DEVZONE_CONFIG)
				continue;
			if (device_locs[i].zone == DEVZONE_DATA && device_locs[i].is_genkey)
				continue;

			ret = atcacert_get_device_data(cert_def, cert, cert_size, &device_locs[i], data);
			if (ret != ATCACERT_E_SUCCESS) return ret;

			start_block = device_locs[i].offset / 32;
			end_block = (device_locs[i].offset + device_locs[i].count) / 32;
			for (block = start_block; block < end_block; block++) {
				ret = atcab_write_zone(device_locs[i].zone, device_locs[i].slot, (uint8_t)block, 0, &data[(block - start_block) * 32], 32);
				if (ret != ATCA_SUCCESS) return ret;
			}
		}		

	} while (0);

	return ret;
}

uint8_t aws_prov_write_user_data(uint8_t offset, uint8_t* data, uint32_t len)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	uint8_t userData[AWS_HOST_ADDR_MAX];
	size_t write_size;

	memset(userData, 0x00, sizeof(userData));
	memcpy(userData, data, len);

	if (offset == AWS_USER_DATA_OFFSET_SSID_LEN || offset == AWS_USER_DATA_OFFSET_PSK_LEN
		|| offset == AWS_USER_DATA_OFFSET_HOST_LEN 	|| offset == AWS_USER_DATA_OFFSET_THING_LEN) {
		write_size = sizeof(size_t);
	} else if (offset == AWS_USER_DATA_OFFSET_HOST) {
		write_size = sizeof(userData);
	} else {
		write_size = sizeof(userData) / 2;
	}

	status = atcab_write_bytes_zone(ATCA_ZONE_DATA, TLS_SLOT8_ENC_STORE, offset, userData, write_size);
	if (status != ATCA_SUCCESS) {
		AWS_ERROR("Failed to write user data!(%d)", status);
		status = AWS_E_CRYPTO_FAILURE;
	}

	return status;
}

uint8_t aws_prov_sign_digest(char* command, uint8_t* response, uint16_t* response_length)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	uint8_t *data_buffer;
	uint16_t buffer_length = 0;
	
	*response_length = 0;

	do {

		status = aws_prov_extract_data_load_tokens((const char*)command, &buffer_length, &data_buffer, '(', ',');
		if (status != KIT_STATUS_SUCCESS)
			break;

		if (*data_buffer != TLS_SLOT_AUTH_PRIV) {
			status = KIT_STATUS_INVALID_PARAMS;
			break;
		}

		status = aws_prov_extract_data_load_tokens((const char*)command + (buffer_length * 2 + 1), &buffer_length, &data_buffer, ',', ')');
		if (status != KIT_STATUS_SUCCESS)
			break;

		if (buffer_length != ATCA_SHA_DIGEST_SIZE) {
			status = KIT_STATUS_INVALID_PARAMS;
			break;
		}
		
		status = atcab_sign(TLS_SLOT_AUTH_PRIV, data_buffer, response);
		if (status != ATCA_SUCCESS)
			break;
		
		*response_length = VERIFY_256_SIGNATURE_SIZE;

	} while (0);
	
	return status;
}

uint8_t aws_prov_save_host_thing(char* command, uint8_t* response, uint16_t* response_length)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	uint8_t *data_buffer, dataLen[ATCA_WORD_SIZE];
	uint16_t buffer_length = 0;
	uint32_t bufLen = 0;

	*response_length = 0;

	do {

		status = aws_prov_extract_data_load_tokens((const char*)command, &buffer_length, &data_buffer, '(', ',');
		if (status != KIT_STATUS_SUCCESS)
			break;

		bufLen = buffer_length;
		memset(dataLen, 0x00, sizeof(dataLen));
		dataLen[0] = (bufLen >> 0) & 0xFF;
		dataLen[1] = (bufLen >> 8) & 0xFF;
		dataLen[2] = (bufLen >> 16) & 0xFF;
		dataLen[3] = (bufLen >> 24) & 0xFF;
		status = aws_prov_write_user_data(AWS_USER_DATA_OFFSET_HOST_LEN, dataLen, bufLen);
		if (status != KIT_STATUS_SUCCESS)
			break;

		status = aws_prov_write_user_data(AWS_USER_DATA_OFFSET_HOST, data_buffer, buffer_length);
		if (status != KIT_STATUS_SUCCESS)
			break;

		status = aws_prov_extract_data_load_tokens((const char*)command + (buffer_length * 2 + 1), &buffer_length, &data_buffer, ',', ')');
		if (status != KIT_STATUS_SUCCESS)
			break;

		bufLen = buffer_length;
		memset(dataLen, 0x00, sizeof(dataLen));
		dataLen[0] = (bufLen >> 0) & 0xFF;
		dataLen[1] = (bufLen >> 8) & 0xFF;
		dataLen[2] = (bufLen >> 16) & 0xFF;
		dataLen[3] = (bufLen >> 24) & 0xFF;
		status = aws_prov_write_user_data(AWS_USER_DATA_OFFSET_THING_LEN, dataLen, bufLen);
		if (status != KIT_STATUS_SUCCESS)
			break;

		status = aws_prov_write_user_data(AWS_USER_DATA_OFFSET_THING, data_buffer, buffer_length);
		if (status != KIT_STATUS_SUCCESS)
			break;

	} while (0);
	
	return status;
}

uint8_t aws_prov_save_wifi_credential(char* command, uint8_t* response, uint16_t* response_length)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	uint8_t *data_buffer, dataLen[ATCA_WORD_SIZE];
	uint16_t buffer_length = 0;
	uint32_t bufLen = 0;

	*response_length = 0;

	do {

		status = aws_prov_extract_data_load_tokens((const char*)command, &buffer_length, &data_buffer, '(', ',');
		if (status != KIT_STATUS_SUCCESS)
			break;

		bufLen = buffer_length;
		memset(dataLen, 0x00, sizeof(dataLen));
		dataLen[0] = (bufLen >> 0) & 0xFF;
		dataLen[1] = (bufLen >> 8) & 0xFF;
		dataLen[2] = (bufLen >> 16) & 0xFF;
		dataLen[3] = (bufLen >> 24) & 0xFF;
		status = aws_prov_write_user_data(AWS_USER_DATA_OFFSET_SSID_LEN, dataLen, bufLen);
		if (status != KIT_STATUS_SUCCESS)
			break;

		status = aws_prov_write_user_data(AWS_USER_DATA_OFFSET_SSID, data_buffer, buffer_length);
		if (status != KIT_STATUS_SUCCESS)
			break;

		status = aws_prov_extract_data_load_tokens((const char*)command + (buffer_length * 2 + 1), &buffer_length, &data_buffer, ',', ')');
		if (status != KIT_STATUS_SUCCESS)
			break;

		bufLen = buffer_length;
		memset(dataLen, 0x00, sizeof(dataLen));
		dataLen[0] = (bufLen >> 0) & 0xFF;
		dataLen[1] = (bufLen >> 8) & 0xFF;
		dataLen[2] = (bufLen >> 16) & 0xFF;
		dataLen[3] = (bufLen >> 24) & 0xFF;
		status = aws_prov_write_user_data(AWS_USER_DATA_OFFSET_PSK_LEN, dataLen, bufLen);
		if (status != KIT_STATUS_SUCCESS)
			break;

		status = aws_prov_write_user_data(AWS_USER_DATA_OFFSET_PSK, data_buffer, buffer_length);
		if (status != KIT_STATUS_SUCCESS)
			break;

	} while (0);
	
	return status;
}

uint8_t aws_prov_save_cert(char* command, uint8_t* response, uint16_t* response_length)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	const atcacert_def_t* cert_def;
	uint8_t der_cert[AWS_CERT_LENGH_MAX];
	size_t der_cert_size = sizeof(der_cert);
	uint8_t *data_buffer;
	char* start_pem = NULL;
	char* end_pem = NULL;
	uint16_t buffer_length = 0;

	*response_length = 0;
	
	do {

		status = aws_prov_extract_data_load_tokens((const char*)command, &buffer_length, &data_buffer, '(', ',');
		if (status != KIT_STATUS_SUCCESS)
			break;
		
		if (*data_buffer == AWS_SIGNER_CERT_ID)
			cert_def = &g_cert_def_1_signer;
		else if (*data_buffer == AWS_DEVICE_CERT_ID)
			cert_def = &g_cert_def_2_device;
		else
			break;

		start_pem = strstr(command, PEM_CERT_BEGIN);
		end_pem = strstr(command, PEM_CERT_END);
		buffer_length = end_pem - start_pem + sizeof(PEM_CERT_END) + 1;
		
		status = atcacert_decode_pem_cert((const char*)start_pem, buffer_length, der_cert, &der_cert_size);
		if (status != ATCA_SUCCESS)
			break;

		status = atcacert_write_cert(cert_def, der_cert, der_cert_size);
		if (status != ATCA_SUCCESS)
			break;

	} while (0);
	
	return status;
}

uint8_t aws_prov_save_signature(char* command, uint8_t* response, uint16_t* response_length)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	uint8_t *data_buffer;
	uint16_t buffer_length = 0;
	uint8_t cert_id;

	*response_length = 0;
	
	do {

		status = aws_prov_extract_data_load_tokens((const char*)command, &buffer_length, &data_buffer, '(', ',');
		if (status != KIT_STATUS_SUCCESS)
			break;
		
		if (*data_buffer != AWS_SIGNER_CERT_ID && *data_buffer != AWS_DEVICE_CERT_ID)
			break;
		else
			cert_id = *data_buffer;

		status = aws_prov_extract_data_load_tokens((const char*)command + (buffer_length * 2 + 1), &buffer_length, &data_buffer, ',', ')');
		if (status != KIT_STATUS_SUCCESS)
			break;
		if (buffer_length != ATCA_SIG_SIZE) 	{
			status = KIT_STATUS_INVALID_PARAMS;
			break;
		}

		status = aws_prov_build_and_save_cert(data_buffer, cert_id);
		if (status != ATCA_SUCCESS)
			break;

	} while (0);
	
	return status;
}

uint8_t aws_prov_get_public_key(char* command, uint8_t* response, uint16_t* response_length)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	uint8_t *data_buffer;
	uint16_t buffer_length = 0;
		
	*response_length = 0;

	do {

		status = aws_prov_extract_data_load((const char*)command, &buffer_length, &data_buffer);
		if (status != KIT_STATUS_SUCCESS)
			break;

		if (*data_buffer != TLS_SLOT_AUTH_PRIV) {
			status = KIT_STATUS_INVALID_PARAMS;
			break;
		}

		status = atcab_get_pubkey(*data_buffer, response);
		if (status != ATCA_SUCCESS)
			break;

		*response_length = ATCA_PUB_KEY_SIZE;

	} while (0);
	
	return status;
}

uint8_t aws_prov_get_cert(char* command, uint8_t* response, uint16_t* response_length)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	uint8_t der_cert[512], pem_cert[AWS_CERT_LENGH_MAX];
	size_t der_cert_size = sizeof(der_cert);
	size_t pem_cert_size = sizeof(pem_cert);
	uint8_t *data_buffer, signer_pub_key[ATCA_PUB_KEY_SIZE] = { 0 };
	uint16_t buffer_length = 0;

	do {

		status = aws_prov_extract_data_load((const char*)command, &buffer_length, &data_buffer);
		if (status != KIT_STATUS_SUCCESS) {
			break;
		}

		if (*data_buffer != AWS_DEVICE_CERT_ID) {
			status = KIT_STATUS_INVALID_PARAMS;
			break;
		}

		status = aws_prov_get_signer_public_key(signer_pub_key);
		if (status != ATCA_SUCCESS) break;

		status = atcacert_read_cert(&g_cert_def_2_device, signer_pub_key, der_cert, &der_cert_size);
		if (status != ATCA_SUCCESS) 
			break;

		status = atcacert_encode_pem_cert(der_cert, der_cert_size, (char*)pem_cert, &pem_cert_size);
		if (status != ATCA_SUCCESS)
			break;

		*response_length = (uint16_t)pem_cert_size;
		memcpy(response, pem_cert, pem_cert_size);

	} while (0);
	
	return status;
}

uint8_t aws_prov_build_device_tbs(char* command, uint8_t* tbs_digest, uint16_t* tbs_size)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	uint8_t *data_buffer;
	uint16_t buffer_length;
	bool lockstate = false;
	uint8_t device_public_key[ATCA_PUB_KEY_SIZE] = { 0 };
	uint8_t device_cert[AWS_CERT_LENGH_MAX];
	size_t  device_cert_size = sizeof(device_cert);
	uint8_t signer_id[] = { 0x00, 0x00 };
	uint8_t configdata[ATCA_CONFIG_SIZE];
	const atcacert_tm_utc_t device_issue_date = {
		.tm_year = 2016 - 1900,
		.tm_mon  = 7 - 1,
		.tm_mday = 19,
		.tm_hour = 20,
		.tm_min  = 0,
		.tm_sec  = 0
	};

	do {

		status = aws_prov_extract_data_load((const char*)command, &buffer_length, &data_buffer);
		if (status != KIT_STATUS_SUCCESS) break;

		status = atcab_is_locked(LOCK_ZONE_CONFIG, &lockstate);
		if (status != ATCA_SUCCESS || !lockstate) break;

		status = atcab_read_config_zone(configdata);
		if (status != ATCA_SUCCESS) break;

		status = atcab_genkey(TLS_SLOT_AUTH_PRIV, device_public_key);
		if (status != ATCA_SUCCESS) break;

		status = aws_prov_build_tbs_cert_digest(&g_cert_def_2_device, device_cert, &device_cert_size, data_buffer,
				device_public_key, signer_id, &device_issue_date, configdata, tbs_digest);
		if (status != ATCA_SUCCESS) break;
		*tbs_size = ATCA_SHA_DIGEST_SIZE;

	} while(0);

	return status;
}

/** \brief This function parses communication commands (ASCII) received from a
*         remote host in the context of an AWS application: commands starting with aw
* \param[in] commandLength
* \param[in] command
* \param[out] resposeLength
* \param[out] response
*/
uint8_t aws_prov_parse_aws_commands(uint16_t commandLength, uint8_t *command, 
												uint16_t *responseLength, uint8_t *response)
{
	uint8_t status = KIT_STATUS_SUCCESS;
	t_aws_kit* kit = aws_kit_get_instance();
	char* pToken = strchr((char *) command, ':');
	*responseLength = 0;
	
	if (!pToken)
	return KIT_STATUS_UNKNOWN_COMMAND;
	
	switch (pToken[1]) 
	{
		// ------------------ "aw[s]:i(signer public key)" ------------------
		case 'I':
		case 'i':
			status = aws_prov_build_device_tbs(pToken + 1, response, responseLength);
			break;
		// ------------------ "aw[s]:g(identifier)" ------------------
		case 'G':
		case 'g':
			status = aws_prov_get_cert(pToken + 1, response, responseLength);
			break;
		// ------------------ "aw[s]:p(slotId)" ------------------
		case 'p':
		case 'P':
			status = aws_prov_get_public_key(pToken + 1, response, responseLength);
			break;
		break;

		case 'S':
		case 's':
			switch (pToken[2])
			{
				// ------------------ aw[s]:ss(certId,signature) ------------------
				case 'S':
				case 's':	
					status = aws_prov_save_signature(pToken + 2, response, responseLength);
				break;
				// ------------------ aw[s]:sc(Id,Cert) ------------------
				case 'C':
				case 'c':
					status = aws_prov_save_cert(pToken + 2, response, responseLength);
				break;
				// ------------------ aw[s]:sh(Host,Thing) ------------------
				case 'H':
				case 'h':
					status = aws_prov_save_host_thing(pToken + 2, response, responseLength);
				break;
				// ------------------ aw[s]:sw(SSID,Password) ------------------
				case 'W':
				case 'w':
					status = aws_prov_save_wifi_credential(pToken + 2, response, responseLength);
					if (status == KIT_STATUS_SUCCESS)
						kit->noti = NOTI_RUN_MQTT_CLIENT;
				break;
				// ------------------ aw[s]:si(slotId,digest) ------------------
				case 'I':
				case 'i':
					status = aws_prov_sign_digest(pToken + 2, response, responseLength);
				break;
				
				default:
					status = KIT_STATUS_UNKNOWN_COMMAND;
				break;
			} 
		break;
		default :
			status = KIT_STATUS_UNKNOWN_COMMAND;
	}

	return status;
}

/** \brief This handler is to receive and send USB packets back over CDC interface.
 */
void aws_prov_handler(void)
{
	uint16_t rx_length = 0, tx_length = 0;
	uint8_t* tx_buffer = NULL;

   	if ((udi_cdc_is_rx_ready()) && ((rx_length = udi_cdc_get_nb_received_data()) > 0)) {
		
		memset(pucUsbRxBuffer, 0, sizeof(pucUsbRxBuffer));
		memset(pucUsbTxBuffer, 0, sizeof(pucUsbTxBuffer));
		
		rx_length = udi_cdc_get_nb_received_data();
		udi_cdc_read_buf((void *)pucUsbRxBuffer, rx_length);
		tx_buffer = aws_prov_process_usb_packet(rx_length, &tx_length);

		if(udi_cdc_is_tx_ready() && tx_length > 0) {
			udi_cdc_write_buf((const void *)tx_buffer, tx_length);				
		}
   	}	
}

void aws_prov_task(void *params)
{
	uint8_t notiBuffer[1];
	t_aws_kit* kit = aws_kit_get_instance();

	udc_start();

	for (;;) {

		ioport_toggle_pin_level(LED0_GPIO);
		aws_prov_handler();
		if (kit->noti == NOTI_RUN_MQTT_CLIENT) {
			notiBuffer[0] = kit->noti;
			xQueueSendToBack(kit->notiQueue, notiBuffer, 1);
		}

		ioport_toggle_pin_level(LED0_GPIO);
		vTaskDelay(AWS_PROV_TASK_DELAY);
	}
}
