/**
 *
 * \file
 *
 * \brief WINC1500 TLS Client Example.
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
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <wolfssl/internal.h>
#include "atecc508cb.h"
#include "tls/atcatls.h"
#include "tls/atcatls_cfg.h"
#include "atcacert/atcacert_client.h"
#include "cert_def_1_signer.h"
#include "cert_def_2_device.h"

/**
 * \brief Give enc key caller.
 */
ATCA_STATUS atca_tls_set_enc_key(uint8_t* outKey, uint16_t keysize)
{
	int ret = ATCA_SUCCESS;

	do {

		if (outKey == NULL || keysize != ATCA_KEY_SIZE) BREAK(ret, "Failed: invalid param");

		memcpy(outKey, ATCA_TLS_PARENT_ENC_KEY, keysize);

	} while(0);

	return ret;
}

/**
 * \brief Write parent key to be used to read securely PMS.
 */
int atca_tls_init_enc_key(void)
{
	uint8_t ret = ATCA_SUCCESS;

	do {

		ret = atcatls_set_enckey((uint8_t*)ATCA_TLS_PARENT_ENC_KEY, TLS_SLOT_ENC_PARENT, false);
		if (ret != ATCA_SUCCESS) BREAK(ret, "Failed: Write key");

		ret = atcatlsfn_set_get_enckey(atca_tls_set_enc_key);
		if (ret != ATCA_SUCCESS) BREAK(ret, "Failed: Set encrypted key");

	} while(0);

	return ret;
}

/**
 * \brief Create pre master secret using peer's public key and own private key.
 */
int atca_tls_create_pms_cb(WOLFSSL* ssl, unsigned char* pubKey, unsigned int* size, unsigned char inOut)
{
	int ret = ATCA_SUCCESS;
	uint8_t peerPubKey[ECC_BUFSIZE];
	uint32_t peerPubKeyLen = sizeof(peerPubKey);

	do {

		if (ssl->arrays->preMasterSecret == NULL || pubKey == NULL || size == NULL || inOut != 0) BREAK(ret, "Failed: invalid param");

		ret = wc_ecc_export_x963(ssl->peerEccKey, peerPubKey, (word32*)&peerPubKeyLen);
		if (ret != MP_OKAY) BREAK(ret, "Failed: export public key");
		atcab_printbin_label((const uint8_t*)"Peer's public key\r\n", peerPubKey, peerPubKeyLen);

		pubKey[0] = ATCA_PUB_KEY_SIZE + 1;
		pubKey[1] = 0x04;
		ret = atcab_get_pubkey(TLS_SLOT_AUTH_PRIV, &pubKey[2]);
		if (ret != 0) BREAK(ret, "Failed: read device public key");
		*size = ATCA_PUB_KEY_SIZE + 2;

		ret = atcatls_ecdh(TLS_SLOT_AUTH_PRIV, peerPubKey + 1, ssl->arrays->preMasterSecret);
		if (ret != 0) BREAK(ret, "Failed: create PMS");
		ssl->arrays->preMasterSz = ATCA_KEY_SIZE;
		//atcab_printbin_label((const uint8_t*)"Pre Master Secret\r\n", ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);
		atcab_printbin_label((const uint8_t*)"Client public key to be sent\r\n", &pubKey[2], *size - 2);

	} while(0);
	
	return ret;
}

/**
 * \brief Generate random number to create secret.
 */
int atca_tls_get_random_number(uint32_t count, uint8_t* rand_out)
{
	int ret = ATCA_SUCCESS;
	uint8_t i = 0, rnd_num[RANDOM_NUM_SIZE];
	uint32_t copy_count = 0;

	do {

		if (rand_out == NULL) BREAK(ret, "Failed: invalid param");

		while (i < count) {

			ret = atcatls_random(rnd_num);
			if (ret != 0) BREAK(ret, "Failed: create random number");

			copy_count = (count - i > RANDOM_NUM_SIZE) ? RANDOM_NUM_SIZE : count - i;
			memcpy(&rand_out[i], rnd_num, copy_count);
			i += copy_count;
		}
		atcab_printbin_label((const uint8_t*)"Random Number\r\n", rand_out, count);

	} while(0);

	return ret;
}

/**
 * \brief Get signer public key to build device certificate.
 */
int atca_tls_get_signer_public_key(uint8_t *pubKey)
{
	uint8_t ret = ATCA_SUCCESS;
	size_t end_block = 3, start_block = 0;
	uint8_t paddedPubKey[96];

	memset(paddedPubKey, 0x00, sizeof(paddedPubKey));
	for (; start_block < end_block; start_block++) {
		ret = atcab_read_zone(DEVZONE_DATA, TLS_SLOT_SIGNER_PUBKEY, 
							start_block, 0, &paddedPubKey[(start_block - 0) * 32], 32);
		if (ret != ATCA_SUCCESS) return ret;
	}

	memcpy(&pubKey[32], &paddedPubKey[40], 32);
	memcpy(&pubKey[0], &paddedPubKey[4], 32);

	return ret;
}

/**
 * \brief Build signer certificate.
 */
int atca_tls_build_signer_cert(t_atcert* cert)
{
	int ret = ATCACERT_E_SUCCESS;

	do {

		if (cert->signer_der == NULL || cert->signer_pem == NULL) BREAK(ret, "Failed: invalid param");

		//ret = atcatls_get_cert(&g_cert_def_1_signer, g_signer_1_ca_public_key, cert->signer_der, (size_t*)&cert->signer_der_size);
		ret = atcatls_get_cert(&g_cert_def_1_signer, NULL, cert->signer_der, (size_t*)&cert->signer_der_size);
		if (ret != ATCACERT_E_SUCCESS) BREAK(ret, "Failed: read signer certificate");
		atcab_printbin_label((const uint8_t*)"Signer DER certficate\r\n", cert->signer_der, cert->signer_der_size);	

		ret = atcacert_encode_pem_cert(cert->signer_der, cert->signer_der_size, (char*)cert->signer_pem, (size_t*)&cert->signer_pem_size);
		if (cert->signer_pem_size <= 0) BREAK(ret, "Failed: convert signer certificate");
		atcab_printbin_label((const uint8_t*)"Signer PEM certificate\r\n", &cert->signer_pem[0], cert->signer_pem_size);

		ret = atcacert_get_subj_public_key(&g_cert_def_1_signer, cert->signer_der, cert->signer_der_size, cert->signer_pubkey);
		if (ret != ATCACERT_E_SUCCESS) BREAK(ret, "Failed: read signer public key");
		atcab_printbin_label((const uint8_t*)"Signer public key\r\n", cert->signer_pubkey, ATCERT_PUBKEY_SIZE);

	} while(0);

	return ret;
}

/**
 * \brief Build device certificate.
 */
int atca_tls_build_device_cert(t_atcert* cert)
{
	int ret = ATCA_SUCCESS;

	do {

		if (cert->device_der == NULL || cert->device_pem == NULL) BREAK(ret, "Failed: invalid param");

		ret = atcatls_get_cert(&g_cert_def_2_device, cert->signer_pubkey, cert->device_der, (size_t*)&cert->device_der_size);
		if (ret != ATCACERT_E_SUCCESS) BREAK(ret, "Failed: read device certificate");
		atcab_printbin_label((const uint8_t*)"Device DER certificate\r\n", cert->device_der, cert->device_der_size);

		ret = atcacert_encode_pem_cert(cert->device_der, cert->device_der_size, (char*)cert->device_pem, (size_t*)&cert->device_pem_size);
		if (cert->device_pem_size <= 0) BREAK(ret, "Failed: convert device certificate");
		atcab_printbin_label((const uint8_t*)"Device PEM certificate\r\n", cert->device_pem, cert->device_pem_size);

		ret = atcacert_get_subj_public_key(&g_cert_def_2_device, cert->device_der, cert->device_der_size, cert->device_pubkey);
		if (ret != ATCACERT_E_SUCCESS) BREAK(ret, "Failed: read device public key");
		atcab_printbin_label((const uint8_t*)"Device public key\r\n", cert->device_pubkey, ATCERT_PUBKEY_SIZE);

	} while(0);
	
	return ret;
}

/**
 * \brief Sign input digest calculated by SHA256.
 */
int atca_tls_sign_certificate_cb(WOLFSSL* ssl, const byte* in, word32 inSz, byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx)
{
	int ret = ATCA_SUCCESS;
	mp_int r, s;

	do {

		if (in == NULL || out == NULL || outSz == NULL) BREAK(ret, "Failed: invalid param");

		ret = atcatls_sign(TLS_SLOT_AUTH_PRIV, in, out);
		if (ret != ATCA_SUCCESS) BREAK(ret, "Failed: sign digest");

		ret = mp_init_multi(&r, &s, NULL, NULL, NULL, NULL);
		if (ret != MP_OKAY) BREAK(ret, "Failed: init R and S");

	    /* Load R and S */    
		ret = mp_read_unsigned_bin(&r, &out[0], ATCA_KEY_SIZE);
		if (ret != MP_OKAY) {
			goto exit_sign;
		}
		ret = mp_read_unsigned_bin(&s, &out[ATCA_KEY_SIZE], ATCA_KEY_SIZE);
		if (ret != MP_OKAY) {
			goto exit_sign;
		}

	    /* Check for zeros */
		if (mp_iszero(&r) || mp_iszero(&s)) {
			ret = -1;
			goto exit_sign;        
		}

		/* convert mp_ints to ECDSA sig, initializes r and s internally */
		ret = StoreECC_DSA_Sig(out, outSz, &r, &s);
		if (ret != MP_OKAY) {
			goto exit_sign;      
		}

exit_sign:
		mp_clear(&r);
		mp_clear(&s);

		atcab_printbin_label((const uint8_t*)"Der Encoded Signature\r\n", out, *outSz);

	} while(0);

	return ret;
}

/**
 * \brief Verify signature received from peers to prove peer's private key.
 */
int atca_tls_verify_signature_cb(WOLFSSL* ssl, const byte* sig, word32 sigSz, const byte* hash, word32 hashSz, const byte* key, word32 keySz, int* result, void* ctx)
{
	int ret = ATCA_SUCCESS;
	bool verified = FALSE;
	uint8_t raw_sigature[ATCA_SIG_SIZE];	
	mp_int r, s;

	do {

		if (key == NULL || sig == NULL || hash == NULL || result == NULL) BREAK(ret, "Failed: invalid param");

	    memset(&r, 0, sizeof(r));
	    memset(&s, 0, sizeof(s));

	    ret = DecodeECC_DSA_Sig(sig, sigSz, &r, &s);
	    if (ret != MP_OKAY) {
	        return -1;
	    }

	    /* Extract R and S */
	    ret = mp_to_unsigned_bin(&r, &raw_sigature[0]);
	    if (ret != MP_OKAY) {
	        goto exit_verify;
	    }

	    ret = mp_to_unsigned_bin(&s, &raw_sigature[ATCA_KEY_SIZE]);
	    if (ret != MP_OKAY) {
	        goto exit_verify;
	    }

		ret = atcatls_verify(hash, raw_sigature, key + 1, &verified);
		if (ret != 0 || (verified != TRUE)) { 
			BREAK(ret, "Failed: verify signature");
		} else { 
			*result = TRUE;
			BREAK(ret, "Verified: signature");
		}

exit_verify:
		mp_clear(&r);
		mp_clear(&s);

	} while(0);

	return ret;
}

#ifdef __cplusplus
}
#endif
