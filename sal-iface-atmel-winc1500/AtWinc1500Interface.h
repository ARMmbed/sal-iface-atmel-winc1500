/**
 *
 * \file
 *
 * \brief WINC1500 Interface APIs.
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

#ifndef _AT_WINC1500_INTERFACE_H_
#define _AT_WINC1500_INTERFACE_H_


class AtWinc1500Interface {
public:

	enum SecType{
	AT_WIFI_SEC_INVALID = 0,
	/*!< Invalid security type.
	*/
	AT_WIFI_SEC_OPEN,
	/*!< Wi-Fi network is not secured.
	*/
	AT_WIFI_SEC_WPA_PSK,
	/*!< Wi-Fi network is secured with WPA/WPA2 personal(PSK).
	*/
	AT_WIFI_SEC_WEP,
	/*!< Security type WEP (40 or 104) OPEN OR SHARED.
	*/
	AT_WIFI_SEC_802_1X
	/*!< Wi-Fi network is secured with WPA/WPA2 Enterprise.IEEE802.1x user-name/password authentication.
	 */
	};

    AtWinc1500Interface();

	~AtWinc1500Interface();

    int init();
    int connect(SecType sec, char* ssid, char* pass);
    void disconnect();

};

#endif /* _AT_WINC1500_INTERFACE_H_ */

