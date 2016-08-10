/**
 *
 * \file
 *
 * \brief AWS kit timer.
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

#ifdef __cplusplus
extern "C" {
#endif

#include <asf.h>
#include "aws_kit_timer.h"

/**
 * \brief Interrupt handler for the RTT.
 *
 * To do something on MS tick increment.
 */
void RTT_Handler(void)
{
	uint32_t ul_status;
	/* Get RTT status */
	ul_status = rtt_get_status(RTT);

	/* Time has changed, to do something */
	if ((ul_status & RTT_SR_RTTINC) == RTT_SR_RTTINC) {
	}

	/* Alarm */
	if ((ul_status & RTT_SR_ALMS) == RTT_SR_ALMS) {
	}
}

/**
 * \brief RTT configuration function.
 *
 * Configure the RTT to generate a one second tick, which triggers the RTTINC
 * interrupt.
 */
void configure_rtt(void)
{
	uint32_t previous_time;

	/* Configure RTT for a 1ms tick interrupt */
	rtt_init(RTT, 32); //32768

	previous_time = rtt_read_timer_value(RTT);
	while (previous_time == rtt_read_timer_value(RTT));

	/* Enable RTT interrupt */
	NVIC_DisableIRQ(RTT_IRQn);
	NVIC_ClearPendingIRQ(RTT_IRQn);
	NVIC_SetPriority(RTT_IRQn, 0);
	NVIC_EnableIRQ(RTT_IRQn);
	rtt_enable_interrupt(RTT, RTT_MR_RTTINCIEN);
}

int _gettimeofday(struct timeval *tv, void *tzvp)
{
	uint32_t ms_tick = 0;

	if (!tv) return -1;

	ms_tick = rtt_read_timer_value(RTT);
	tv->tv_sec =  ms_tick / 1000;
	tv->tv_usec = ms_tick * 1000;

	return 0;
}

bool aws_kit_timer_expired(Timer *timer)
{
	struct timeval now, res;

	gettimeofday(&now, NULL);
	timersub(&timer->end_time, &now, &res);

	return res.tv_sec < 0 || (res.tv_sec == 0 && res.tv_usec <= 0);
}

void aws_kit_countdown_ms(Timer *timer, uint32_t timeout)
{
	struct timeval now, interval = {timeout / 1000, (int)((timeout % 1000) * 1000)};

	gettimeofday(&now, NULL);
	timeradd(&now, &interval, &timer->end_time);
}

void aws_kit_countdown_sec(Timer *timer, uint32_t timeout)
{
	struct timeval now;
	struct timeval interval = {timeout, 0};

	gettimeofday(&now, NULL);
	timeradd(&now, &interval, &timer->end_time);
}

uint32_t aws_kit_left_ms(Timer *timer)
{
	uint32_t result_ms = 0;
	struct timeval now, res;

	gettimeofday(&now, NULL);	
	timersub(&timer->end_time, &now, &res);
	if(res.tv_sec >= 0) {
		result_ms = (uint32_t) (res.tv_sec * 1000 + res.tv_usec / 1000);
	}

	return result_ms;
}

void aws_kit_init_timer(Timer *timer)
{
	timer->end_time = (struct timeval) {0, 0};
}

#ifdef __cplusplus
}
#endif
