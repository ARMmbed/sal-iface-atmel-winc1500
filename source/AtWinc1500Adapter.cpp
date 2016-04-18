/**
 *
 * \file
 *
 * \brief WINC1500 Adapter APIs.
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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sal/socket_api.h"

#include "AtWinc1500Adapter.h"
#include "driver/include/m2m_wifi.h"
#include "socket/include/socket.h"
#include "bsp/include/nm_bsp.h"

#include "core-util/FunctionPointer.h"
#include "mbed-drivers/mbed.h"

using namespace mbed::util;


#define IPV4_BYTE(val, index)           		((val >> (index * 8)) & 0xFF)
#define AT_WIFI_M2M_BUFFER_SIZE 	SOCKET_BUFFER_MAX_LENGTH

#define SOCKET_ABSTRACTION_LAYER_VERSION 1

typedef enum {
	AT_STATE_UNKNOWN = 0,
	AT_WIFI_CONNECT,
	AT_WIFI_DISCONNECT,
	AT_WIFI_HOSTNAME,
	AT_SOCK_BIND,
	AT_SOCK_LISTEN,						// 5
	AT_SOCK_ACCEPT,
	AT_SOCK_CONNECT,
	AT_SOCK_SEND,
	AT_SOCK_SENDTO,
	AT_SOCK_RECV,							// 10
	AT_SOCK_RECVFROM
}wifiState;

typedef struct{
	void* 			mbedSock;
	void* 			recvBuf;
	uint32_t		remoteIp;
	uint16_t		remotePort;
	uint16_t 		recvLen;
	uint8_t 		sockType;
	uint8_t			bIsBound;
	uint8_t 		bIsUsed;
	uint8_t			bIsConnected;
	uint8_t			bIsAccepted;
	uint8_t			bIsFirstRecvCalled;
	int8_t			listenSocketHandle;
	int8_t			socketHandle;
}tWincSock;

/** Receive buffer definition. */
static uint8_t gReceivedBuf[AT_WIFI_M2M_BUFFER_SIZE] = {0,};

static uint8_t gWifiConnected;
static wifiState gCbState = AT_STATE_UNKNOWN;

static struct socket *gMbedSock = NULL;

static tWincSock gSockList[MAX_SOCKET] = {0,};

uint8_t gApSSId[64] = {0,};
uint8_t gApPass[24] = {0,};
uint8_t gSecType = M2M_WIFI_SEC_WPA_PSK;


///////////////////////////////////////////////////////////////////////////////////////////////////////////////
/** Forward declaration of the socket api */

static void winc_event_loop(int32_t checkState)
{
	while(1)
	{
		m2m_wifi_handle_events(NULL);

		if (checkState == gCbState)
		{
			gCbState = AT_STATE_UNKNOWN;
			break;
		}
	}
}

static void sock_event_loop_for_data(void)
{
	m2m_wifi_handle_events(NULL);
}

static void send_resolve_event(struct socket *sock, uint8_t *hostName, uint32_t hostIp)
{
	if (!sock)
	{
		M2M_ERR("send_resolve_event:: sock(mbed) is NULL \n");
		return;
	}

	M2M_INFO("send_resolve_event:: Host Name : %s \n", hostName);
	M2M_INFO("send_resolve_event:: Host IP : %d.%d.%d.%d \n", (int)IPV4_BYTE(hostIp, 0), (int)IPV4_BYTE(hostIp, 1), 
		(int)IPV4_BYTE(hostIp, 2), (int)IPV4_BYTE(hostIp, 3));
	
	socket_api_handler_t mEventHandler = (socket_api_handler_t) sock->handler;
	socket_event_t e = {SOCKET_EVENT_NONE, };
	if (hostIp == 0) {
		e.event = SOCKET_EVENT_ERROR;
		e.i.e = SOCKET_ERROR_DNS_FAILED;
	} else {
		e.event = SOCKET_EVENT_DNS;
		socket_addr_set_ipv4_addr(&e.i.d.addr, hostIp);
		e.i.d.domain = (const char*)hostName;
	}
	
	sock->event = &e;
	mEventHandler();
	sock->event = NULL;
}

static void socket_resolve_cb(uint8_t *hostName, uint32_t hostIp)
{
	gCbState = AT_WIFI_HOSTNAME;
	
	send_resolve_event(gMbedSock, hostName, hostIp);
}

static void socket_noti_cb(SOCKET sock, uint8_t u8Msg, void *pvMsg)
{	
	switch (u8Msg) 
	{
		/* Socket(Server) bind */
		case SOCKET_MSG_BIND:
		{
			tstrSocketBindMsg *pstrBind = (tstrSocketBindMsg *)pvMsg;			
			if (pstrBind && pstrBind->status != 0)			
			{				
				M2M_ERR("socket_cb: bind error! \n");		
			}

			gCbState = AT_SOCK_BIND;
			
			break;
		}
			
		/* Socket(Server) listen */	
		case SOCKET_MSG_LISTEN:
		{
			tstrSocketListenMsg *pstrListen = (tstrSocketListenMsg *)pvMsg;			
			if (pstrListen && pstrListen->status != 0)
			{
				M2M_ERR("socket_cb: listen error! \n");
			}

			gCbState = AT_SOCK_LISTEN;
			break;
		}
		
		/* Socket(Server) accept */		
		case SOCKET_MSG_ACCEPT:
		{
			socket_error_t err = SOCKET_ERROR_NONE;
			tstrSocketAcceptMsg *pstrAccept = (tstrSocketAcceptMsg *)pvMsg;			
			if (pstrAccept)			
			{								
				accept(sock, (struct sockaddr *)&pstrAccept->strAddr, NULL);		
				if (pstrAccept->sock >= 0)				
				{
					int idx = pstrAccept->sock;
					//M2M_INFO("socket_cb: STA Accepted socket(%d) is created.\n", pstrAccept->sock);
					
					if (!gSockList[idx].bIsUsed && !gSockList[idx].bIsAccepted)
					{
						gSockList[idx].bIsUsed = 1;
						gSockList[idx].bIsAccepted = 1;
						gSockList[idx].socketHandle = pstrAccept->sock;
						gSockList[idx].listenSocketHandle = sock;
						gSockList[idx].remoteIp = pstrAccept->strAddr.sin_addr.s_addr;
						gSockList[idx].remotePort = pstrAccept->strAddr.sin_port;
						gSockList[idx].recvBuf = gReceivedBuf;
					}
					else
					{
						M2M_ERR("socket_cb: accept error / sock : %d(accpeted socket) \n", sock );
						err = SOCKET_ERROR_VALUE;
					}
				}					
			}			
			else			
			{				
				M2M_ERR("socket_cb: accept error / sock : %d \n", sock );
				err = SOCKET_ERROR_NULL_PTR;
			}

			if (err != SOCKET_ERROR_NONE)
			{
				socket_event_t e = {SOCKET_EVENT_NONE, };
				socket_api_handler_t mEventHandler = NULL;

				struct socket* mSock = (struct socket *)gSockList[sock].mbedSock;

				if (!mSock)
				{
					M2M_ERR("socket_cb: accept error / mbed socket is NULL \n", sock );
				}
				else
				{
					mEventHandler = (socket_api_handler_t)mSock->handler;

					e.event = SOCKET_EVENT_ERROR;
					e.i.e = err;

					mSock->event = &e;
					mEventHandler();
					mSock->event = NULL;
				}
			}

			gCbState = AT_SOCK_ACCEPT;
			break;
		}
			
		/* Socket(Client) connected */
		case SOCKET_MSG_CONNECT:
		{
			tstrSocketConnectMsg *pstrConnect = (tstrSocketConnectMsg *)pvMsg;
			if (!pstrConnect || pstrConnect->s8Error < 0)
			{
				socket_event_t e = {SOCKET_EVENT_NONE, };
				socket_api_handler_t mEventHandler = NULL;

				struct socket *mSock = (struct socket *)gSockList[sock].mbedSock;
				
				M2M_ERR("socket_cb: connect error!(sock:%d) \n", sock);

				if (!mSock)
				{
					M2M_ERR("socket_cb: connect error / mbed socket is NULL \n", sock );
				}
				else
				{
					mEventHandler = (socket_api_handler_t)mSock->handler;

					e.event = SOCKET_EVENT_ERROR;
					e.i.e = SOCKET_ERROR_NO_CONNECTION;

					mSock->event = &e;
					mEventHandler();
					mSock->event = NULL;
				}

				
			}
			else
			{				
				M2M_INFO("socket_cb: connect success!(sock:%d) \n", sock);
			}

			gCbState = AT_SOCK_CONNECT;
			break;
		}
		
		/* Message send */
		case SOCKET_MSG_SEND:
		{
			int16_t *size = (int16_t *)pvMsg;
			struct socket *mSock = (struct socket *)gSockList[sock].mbedSock;
			
			socket_event_t e = {SOCKET_EVENT_NONE, };
			socket_api_handler_t mEventHandler = mSock->handler;

			//M2M_INFO("socket_cb: send(sock=%d, len=%d) \n", sock, *size);

			if (!mSock)
			{
				M2M_ERR("socket_cb: send error / mbed socket is NULL \n", sock );
			}
			else
			{
				e.event = SOCKET_EVENT_TX_DONE;
				//e.sock = mSock;
				e.i.t.sentbytes = *size;
				mSock->event = &e;
				mEventHandler();
				mSock->event = NULL;
			}
			
			break;
		}
		
		case SOCKET_MSG_SENDTO:
		{
			int16_t *size = (int16_t *)pvMsg;
			struct socket *mSock = (struct socket *)gSockList[sock].mbedSock;
			
			socket_event_t e = {SOCKET_EVENT_NONE, };
			socket_api_handler_t mEventHandler = mSock->handler;

			//M2M_INFO("socket_cb: sendto(sock=%d, len=%d) \n", sock, *size);

			if (!mSock)
			{
				M2M_ERR("socket_cb: sendto error / mbed socket is NULL \n", sock );
			}
			else
			{
				e.event = SOCKET_EVENT_TX_DONE;
				//e.sock = mSock;
				e.i.t.sentbytes = *size;
				mSock->event = &e;
				mEventHandler();
				mSock->event = NULL;
			}
			
			break;
		}

		/* Message receive */
		case SOCKET_MSG_RECV:
		{
			tstrSocketRecvMsg *pstrRecv = (tstrSocketRecvMsg *)pvMsg;
			struct socket *mSock = (struct socket *)gSockList[sock].mbedSock;

			socket_event_t e = {SOCKET_EVENT_NONE, };
			socket_api_handler_t mEventHandler = NULL;

			if (!mSock)
			{
				M2M_ERR("socket_cb: recv error / mbed socket is NULL \n", sock );
				break;
			}

			mEventHandler = (socket_api_handler_t)mSock->handler;
			
			if (pstrRecv && pstrRecv->s16BufferSize > 0)
			{
				int ipaddr = pstrRecv->strRemoteAddr.sin_addr.s_addr;
				
				//M2M_INFO("socket_cb: Recv Success, received data size : %d \n", pstrRecv->s16BufferSize);
				//M2M_INFO("Host IP : %d.%d.%d.%d, Port : %d \n", (int)IPV4_BYTE(ipaddr, 0), (int)IPV4_BYTE(ipaddr, 1),	
					//(int)IPV4_BYTE(ipaddr, 2), (int)IPV4_BYTE(ipaddr, 3), pstrRecv->strRemoteAddr.sin_port);

				e.event = SOCKET_EVENT_RX_DONE;
				gSockList[sock].recvLen = pstrRecv->s16BufferSize;
				gSockList[sock].remoteIp = ipaddr;
				gSockList[sock].remotePort = _ntohs(pstrRecv->strRemoteAddr.sin_port);
			}
			else
			{
				M2M_ERR("socket_cb: Recv Wrong, received data is empty / sock : %d, pstrRecv->s16BufferSize : %d \n", sock, pstrRecv->s16BufferSize );

				e.event = SOCKET_EVENT_ERROR;
				e.i.e = SOCKET_ERROR_BAD_ARGUMENT;
			}
			
		    mSock->event = &e;
		    mEventHandler();
		    mSock->event = NULL;
			
			break;
		}
		
		case SOCKET_MSG_RECVFROM:
		{
			tstrSocketRecvMsg *pstrRecv = (tstrSocketRecvMsg *)pvMsg;
			struct socket *mSock = (struct socket *)gSockList[sock].mbedSock;
			
			socket_event_t e = {SOCKET_EVENT_NONE, };
			socket_api_handler_t mEventHandler = NULL;

			if (!mSock)
			{
				M2M_ERR("socket_cb: recvfrom error / mbed socket is NULL \n", sock );
				break;
			}

			mEventHandler = (socket_api_handler_t)mSock->handler;
			
			if (pstrRecv && pstrRecv->s16BufferSize > 0)
			{
				int ipaddr = pstrRecv->strRemoteAddr.sin_addr.s_addr;
				//M2M_INFO("socket_cb: Recvfrom(%d) success, received data size : %d \n", sock, pstrRecv->s16BufferSize);
				//M2M_INFO(" Host IP : %d.%d.%d.%d, Port : %d \n", (int)IPV4_BYTE(ipaddr, 0), (int)IPV4_BYTE(ipaddr, 1),	
					//(int)IPV4_BYTE(ipaddr, 2), (int)IPV4_BYTE(ipaddr, 3), _ntohs(pstrRecv->strRemoteAddr.sin_port));
				
				e.event = SOCKET_EVENT_RX_DONE;
				gSockList[sock].recvLen = pstrRecv->s16BufferSize;
				gSockList[sock].remoteIp = ipaddr;
				gSockList[sock].remotePort = _ntohs(pstrRecv->strRemoteAddr.sin_port);
			}
			else
			{
				M2M_ERR("socket_cb: Recvfrom Wrong, received data is empty / sock : %d, pstrRecv->s16BufferSize : %d \n", sock, pstrRecv->s16BufferSize );
				
				e.event = SOCKET_EVENT_ERROR;
				e.i.e = SOCKET_ERROR_BAD_ARGUMENT;
			}

			mSock->event = &e;
			mEventHandler();
			mSock->event = NULL;
			
			break;
		}

		default:
			break;
	}
}

static void at_sock_set_event_handler_to_scheduler()
{
	minar::Scheduler::postCallback(sock_event_loop_for_data).period(minar::milliseconds(100));
}

static void at_sock_init()
{
	M2M_INFO("at_sock_init \n");

	/* Initialize socket module */
	socketInit();
	
	registerSocketCallback(socket_noti_cb, socket_resolve_cb);

	memset(gSockList, 0, sizeof(gSockList));
}

static void* at_sock_open(uint8_t type, void *sock)
{
	int8_t sockHandle = 0;
	int8_t sockIdx = socket(AF_INET, type, 0);

	if (sockIdx < 0 || gSockList[sockIdx].bIsUsed)
	{
		M2M_ERR("at_sock_open:: Error, Not opened socket (socket Idx=%d) \n", sockIdx);
		return NULL;
	}

	M2M_INFO("at_sock_open:: sock %d, type %d \n", sockIdx, type);

	gSockList[sockIdx].socketHandle = sockIdx;
	gSockList[sockIdx].listenSocketHandle = -1;
	gSockList[sockIdx].bIsUsed = 1;
	gSockList[sockIdx].mbedSock = sock;
	gSockList[sockIdx].recvBuf = (void*)gReceivedBuf;
	gSockList[sockIdx].recvLen = 0;
	gSockList[sockIdx].sockType = type;

	return (gSockList + sockIdx);
}

socket_error_t atwinc_socket_error_remap(int32_t sock_err)
{
	socket_error_t err = SOCKET_ERROR_UNKNOWN;
	switch (sock_err) {
		case SOCK_ERR_NO_ERROR:
			err = SOCKET_ERROR_NONE;
			break;
		case SOCK_ERR_INVALID_ADDRESS:
		case SOCK_ERR_ADDR_IS_REQUIRED:
			err = SOCKET_ERROR_BAD_ADDRESS;
			break;
		case SOCK_ERR_ADDR_ALREADY_IN_USE:
			err = SOCKET_ERROR_ADDRESS_IN_USE;
			break;
		case SOCK_ERR_MAX_TCP_SOCK:
		case SOCK_ERR_MAX_UDP_SOCK:
		case SOCK_ERR_BUFFER_FULL:
			break;
		case SOCK_ERR_INVALID_ARG:
			err = SOCKET_ERROR_BAD_ARGUMENT;
			break;
		case SOCK_ERR_INVALID:
			err = SOCKET_ERROR_VALUE;
			break;
		case SOCK_ERR_CONN_ABORTED:
			err = SOCKET_ERROR_VALUE;
			break;
		case SOCK_ERR_TIMEOUT:
			err = SOCKET_ERROR_TIMEOUT;
			break;			
	}

	return err;
}

static socket_error_t atwinc_init()
{
	M2M_INFO("atwinc_init:: \n");
		
	return SOCKET_ERROR_NONE;
}

static socket_api_handler_t atwinc_socket_periodic_task(const struct socket * sock)
{
	M2M_INFO("atwinc_socket_periodic_task:: Not implmented \n");
	
	return NULL;
}

static uint32_t atwinc_socket_periodic_interval(const struct socket * sock)
{
	M2M_INFO("atwinc_socket_periodic_interval:: Not implmented \n");
	
	return 0;
}

static socket_error_t atwinc_socket_resolve(struct socket *sock, const char *address)
{
	int32_t ret = SOCK_ERR_NO_ERROR;
	int32_t i, flg = 0;

	if (!sock || !address)
		return SOCKET_ERROR_NULL_PTR;

	M2M_INFO("atwinc_socket_resolve:: %s \n", address);

	for(i=0; i<strlen(address); i++)
	{
		if( (address[i] < '0' || address[i] > '9') && address[i] != '.')
		{
			flg = 1;
			break;
		}
	}

	if (!flg)
	{
		uint32_t u32Ip = nmi_inet_addr((char *)address);
		//M2M_INFO("Get1 Host IP : %d.%d.%d.%d\r\n", (int)IPV4_BYTE(u32Ip, 0), (int)IPV4_BYTE(u32Ip, 1),
		//(int)IPV4_BYTE(u32Ip, 2), (int)IPV4_BYTE(u32Ip, 3));

		send_resolve_event(sock, (uint8_t *)address, u32Ip);
	}
	else
	{
		int32_t ret = gethostbyname((uint8_t *)address);
		if (ret != SOCK_ERR_NO_ERROR)
		{
			M2M_ERR("Error(%d):: socket gethostbyname \n", ret);
		}
		else
		{
			gMbedSock = sock;
			winc_event_loop(AT_WIFI_HOSTNAME);
		}
	}
	
    return atwinc_socket_error_remap(ret);
}

static socket_error_t atwinc_socket_create(struct socket *sock, const socket_address_family_t af, const socket_proto_family_t pf, socket_api_handler_t const handler)
{
	socket_error_t err = SOCKET_ERROR_NONE;

	if (af != SOCKET_AF_INET4)
		return SOCKET_ERROR_BAD_FAMILY;

	if (!sock || !handler)
		return SOCKET_ERROR_NULL_PTR;

	M2M_INFO("atwinc_socket_create:: PF=%d \n", pf);

	if (!gWifiConnected)
	{
		M2M_ERR("Not connected AP \n");
		return SOCKET_ERROR_INTERFACE_ERROR;
	}

	switch (pf) {
		case SOCKET_DGRAM:
		{
			sock->impl = at_sock_open(SOCK_DGRAM, sock);
			break;
		}
		case SOCKET_STREAM:
		{
			sock->impl = at_sock_open(SOCK_STREAM, sock);
			break;
		}
		default:
			return SOCKET_ERROR_BAD_FAMILY;
	}
	
	if (sock->impl)
	{	
		sock->family = pf;
		sock->handler = handler;
		sock->rxBufChain = NULL;
	}
	else
		err = SOCKET_ERROR_NULL_PTR;
	
	return err;
}

static socket_error_t atwinc_socket_accept(struct socket *sock, socket_api_handler_t handler)
{
	M2M_INFO("atwinc_socket_accept:: Not supported \n");
	
	return SOCKET_ERROR_UNIMPLEMENTED;
}

static socket_error_t atwinc_socket_accept_v2(struct socket *listener, struct socket *sock, socket_api_handler_t handler) 
{
	int ret = SOCK_ERR_NO_ERROR;
	tWincSock *wincSock = NULL;

	if (!listener || !sock || !handler)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)listener->impl;

	M2M_INFO("atwinc_socket_accept_v2:: sock : %d \n", wincSock->socketHandle);

	ret = accept(wincSock->socketHandle, NULL, NULL);
	if (ret != SOCK_ERR_NO_ERROR)
	{
		M2M_ERR("Error(%d):: socket accept \n", ret);
	}
	else
	{
		int32_t idx = 0;
		tWincSock *acceptSock = NULL;

		if (!wincSock->bIsAccepted)
		{
			winc_event_loop(AT_SOCK_ACCEPT);
		}

		ret = SOCK_ERR_INVALID;
		
		do
		{
			if (gSockList[idx].listenSocketHandle == wincSock->socketHandle)
			{
				acceptSock = gSockList + idx;
				
				sock->handler = handler;
				sock->rxBufChain = NULL;
				sock->impl = (void *)acceptSock;

				if (!acceptSock->bIsFirstRecvCalled)
				{
					ret = recv(acceptSock->socketHandle, acceptSock->recvBuf, AT_WIFI_M2M_BUFFER_SIZE, 0);
					if (ret != SOCK_ERR_NO_ERROR)
					{
							M2M_ERR("Error(%d):: socket recv \n", ret);
					}

					at_sock_set_event_handler_to_scheduler();

					acceptSock->bIsFirstRecvCalled = 1;
				}
				break;
			}
		}while(idx++ < MAX_SOCKET);
	}
	
	return atwinc_socket_error_remap(ret);
}

static socket_error_t atwinc_socket_close(struct socket *sock)
{
	int ret = SOCK_ERR_NO_ERROR;
	tWincSock *wincSock = NULL;

	if (!sock || !sock->impl)
		return SOCKET_ERROR_BAD_ARGUMENT;
	
	wincSock = (tWincSock *)sock->impl;

	M2M_INFO("atwinc_socket_close, sock:: %d \n", wincSock->socketHandle);

	ret = close(wincSock->socketHandle);
	if (ret != SOCK_ERR_NO_ERROR)
	{
		M2M_ERR("Error(%d):: socket close \n", ret);
	}
	else
	{
		memset(wincSock, 0, sizeof(tWincSock));
		wincSock->socketHandle = -1;
		wincSock->listenSocketHandle = -1;
	}
	
	return atwinc_socket_error_remap(ret);
}

static socket_error_t atwinc_socket_destroy(struct socket *sock)
{
	socketDeinit();
	
	return SOCKET_ERROR_NONE;
}

static socket_error_t atwinc_socket_connect(struct socket *sock, const struct socket_addr *address, const uint16_t port)
{
	int ret = SOCK_ERR_NO_ERROR;
	tWincSock *wincSock = NULL;

	struct sockaddr_in addr = {0,};
	uint32_t hostIp = 0;

	if (!sock || !sock->impl || !address)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)sock->impl;
	hostIp = socket_addr_get_ipv4_addr(address);

	M2M_INFO("atwinc_socket_connect:: sock : %d(IP Addr : %08X, Port : %d) \n", wincSock->socketHandle, hostIp, port);

	wincSock->remoteIp = hostIp;
	wincSock->remotePort = port;
	
	addr.sin_family = AF_INET;
	addr.sin_port = _htons(port);
	addr.sin_addr.s_addr = hostIp;
	
	ret = connect(wincSock->socketHandle, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (ret != SOCK_ERR_NO_ERROR)
	{
		M2M_ERR("Error(%d):: socket accept \n", ret);
	}
	else
	{
		winc_event_loop(AT_SOCK_CONNECT);

		if (!wincSock->bIsFirstRecvCalled)
		{
			ret = recv(wincSock->socketHandle, wincSock->recvBuf, AT_WIFI_M2M_BUFFER_SIZE, 0);
			if (ret != SOCK_ERR_NO_ERROR)
			{
					M2M_ERR("Error(%d):: socket recv \n", ret);
			}

			at_sock_set_event_handler_to_scheduler();

			wincSock->bIsFirstRecvCalled = 1;
		}
	}
	
	return atwinc_socket_error_remap(ret);
}

static socket_error_t atwinc_str2addr(const struct socket *sock, struct socket_addr *address, const char *addr)
{
	socket_error_t err = SOCKET_ERROR_NONE;
	uint32_t intIpAddr = 0;

	if (!address || !addr)
		return SOCKET_ERROR_NULL_PTR;

	M2M_INFO("atwinc_str2addr:: IP Address : %s \n", addr);

	intIpAddr= nmi_inet_addr((char *)addr);

	socket_addr_set_ipv4_addr(address, intIpAddr);
	
    return err;
}

static socket_error_t atwinc_start_listen(struct socket *sock, uint32_t backlog)
{
	int ret = SOCK_ERR_NO_ERROR;
	tWincSock* wincSock = NULL;

	if (!sock || !sock->impl)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)sock->impl;

	M2M_INFO("atwinc_start_listen:: sock : %d(backlog : %d) \n", wincSock->socketHandle, backlog);

	ret = listen(wincSock->socketHandle, (uint8_t)backlog);
	if (ret != SOCK_ERR_NO_ERROR)
	{
		M2M_ERR("Error(%d):: socket listen\r\n", ret);
	}
	else
	{
		winc_event_loop(AT_SOCK_LISTEN);
	}
	
	return atwinc_socket_error_remap(ret);
}

static socket_error_t atwinc_stop_listen(struct socket *sock)
{
	M2M_INFO("atwinc_stop_listen:: Not implmented \n");

	return SOCKET_ERROR_UNIMPLEMENTED;
}

static socket_error_t atwinc_socket_bind(struct socket *sock, const struct socket_addr *address, const uint16_t port)
{
	int ret = SOCK_ERR_NO_ERROR;
	tWincSock *wincSock = NULL;

	struct sockaddr_in addr = {0,};
	uint32_t hostIp = 0; 

	if (!sock || !sock->impl || !address)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)sock->impl;
	hostIp = socket_addr_get_ipv4_addr(address);
	
	M2M_INFO("atwinc_socket_bind:: sock : %d(IP Addr : %08X, Port : %d) \n", wincSock->socketHandle, hostIp, port);
	
	addr.sin_family = AF_INET;
	addr.sin_port = _htons(port);
	addr.sin_addr.s_addr = hostIp;

	ret = bind(wincSock->socketHandle, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (ret != SOCK_ERR_NO_ERROR)
	{
		M2M_ERR("Error(%d) : atwinc_socket_bind \n", ret);
	}
	else
	{
		winc_event_loop(AT_SOCK_BIND);
		wincSock->bIsBound = 1;

		if (wincSock->sockType == SOCK_DGRAM && !wincSock->bIsFirstRecvCalled)
		{
			ret = recvfrom(wincSock->socketHandle, wincSock->recvBuf, AT_WIFI_M2M_BUFFER_SIZE, 0);
			if (ret != SOCK_ERR_NO_ERROR)
			{
					M2M_ERR("Error(%d):: socket recv \n", ret);
			}

			at_sock_set_event_handler_to_scheduler();

			wincSock->bIsFirstRecvCalled = 1;
		}
	}

	return atwinc_socket_error_remap(ret);
}

static uint8_t atwinc_socket_is_connected(const struct socket *sock) 
{
	int ret = SOCK_ERR_NO_ERROR;
	tWincSock *wincSock = NULL;

	if (!sock || !sock->impl)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)sock->impl;
	
	M2M_INFO("atwinc_socket_bind:: sock : %d(connected : %d) \n", wincSock->socketHandle, wincSock->bIsConnected);
	
	return wincSock->bIsConnected;
}

static uint8_t atwinc_socket_is_bound(const struct socket *sock)
{
	tWincSock *wincSock = NULL;

	if (!sock || !sock->impl)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)sock->impl;
	
	M2M_INFO("atwinc_socket_is_bound:: %d \n", wincSock->bIsBound);
	
	return wincSock->bIsBound;
}

static socket_error_t atwinc_socket_send(struct socket *sock, const void *buf, const size_t len)
{
    int ret = SOCK_ERR_NO_ERROR;
	tWincSock *wincSock = NULL;

	if (!sock || !sock->impl || !buf)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)sock->impl;

	M2M_INFO("atwinc_socket_send:: sock : %d \n", wincSock->socketHandle);

	do
	{
		ret = send(wincSock->socketHandle, (void*)buf, (uint16)len, 0);
		if (ret != SOCK_ERR_NO_ERROR)
		{
				M2M_ERR("Error(%d):: socket send \n", ret);
		}
	} while(ret == SOCK_ERR_BUFFER_FULL);
	
	return atwinc_socket_error_remap(ret);
}

static socket_error_t atwinc_socket_send_to(struct socket *sock, const void *buf, const size_t len, const struct socket_addr *address, const uint16_t port)
{
	int ret = SOCK_ERR_NO_ERROR;
	tWincSock *wincSock = NULL;

	struct sockaddr_in addr = {0,};
	uint32_t hostIp = 0;

	if (!sock || !sock->impl || !buf || !address)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)sock->impl;
	hostIp = socket_addr_get_ipv4_addr(address);

	M2M_INFO("atwinc_socket_send_to:: sock : %d, len : %d \n", wincSock->socketHandle, len);

	//M2M_INFO(" :: Host IP : %d.%d.%d.%d, Port : %d\r\n", (int)IPV4_BYTE(hostIp, 0), (int)IPV4_BYTE(hostIp, 1), 
	//	(int)IPV4_BYTE(hostIp, 2), (int)IPV4_BYTE(hostIp, 3), port);
	
	addr.sin_family = AF_INET;
	addr.sin_port = _htons(port);
	addr.sin_addr.s_addr = hostIp;

	do
	{
		ret = sendto(wincSock->socketHandle, (void*)buf, (uint16)len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
		if (ret != SOCK_ERR_NO_ERROR)
		{
			M2M_ERR("Error(%d) : socket sendto \n", ret);
		}
		else
		{
			if (wincSock->sockType == SOCK_DGRAM && !wincSock->bIsBound && !wincSock->bIsFirstRecvCalled)
			{
				ret = recvfrom(wincSock->socketHandle, wincSock->recvBuf, AT_WIFI_M2M_BUFFER_SIZE, 0);
				if (ret != SOCK_ERR_NO_ERROR)
				{
					M2M_ERR("Error(%d):: socket recv \n", ret);
				}
				else
				{
					at_sock_set_event_handler_to_scheduler();
					wincSock->bIsFirstRecvCalled = 1;
				}
			}
		}
	} while(ret == SOCK_ERR_BUFFER_FULL);
	
	return atwinc_socket_error_remap(ret);
}

static socket_error_t atwinc_socket_recv(struct socket *sock, void * buf, size_t *len)
{
	int ret = SOCK_ERR_NO_ERROR;
	tWincSock *wincSock =NULL;

	if (!sock || !sock->impl || !buf || !len)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)sock->impl;

	M2M_INFO("atwinc_socket_recv:: sock : %d, port : %d, len : %d \n", wincSock->socketHandle, wincSock->recvLen);

	if (wincSock->recvBuf && wincSock->recvLen)
	{
		memcpy(buf, wincSock->recvBuf, wincSock->recvLen);
		*len = (size_t)wincSock->recvLen;

		memset(wincSock->recvBuf, 0, AT_WIFI_M2M_BUFFER_SIZE);

		ret = recv(wincSock->socketHandle, wincSock->recvBuf, AT_WIFI_M2M_BUFFER_SIZE, 0);
		if (ret != SOCK_ERR_NO_ERROR)
		{
				M2M_ERR("Error(%d):: socket recv \n", ret);
		}
	}
	else
	{
		M2M_ERR("Error(%d):: Buffer is NULL or Buffer Length is 0 \n");
		ret = SOCK_ERR_INVALID;
	}
	
	return atwinc_socket_error_remap(ret);
}

static socket_error_t atwinc_socket_recv_from(struct socket *sock, void * buf, size_t *len, struct socket_addr *address, uint16_t *port)
{
	int ret = SOCK_ERR_NO_ERROR;
	tWincSock *wincSock = NULL;

	if (!sock || !sock->impl || !buf || !len || !address || !port)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)sock->impl;

	M2M_INFO("atwinc_socket_recv_from:: sock : %d, port : %d, len : %d \n", wincSock->socketHandle, wincSock->remotePort, wincSock->recvLen);

	if (wincSock->recvBuf && wincSock->recvLen)
	{
		memcpy(buf, wincSock->recvBuf, wincSock->recvLen);
		*len = (size_t)wincSock->recvLen;

		socket_addr_set_ipv4_addr(address, wincSock->remoteIp);
		*port = wincSock->remotePort;
		
		memset(wincSock->recvBuf, 0, AT_WIFI_M2M_BUFFER_SIZE);
		
		ret = recvfrom(wincSock->socketHandle, wincSock->recvBuf, AT_WIFI_M2M_BUFFER_SIZE, 0);
		if (ret != SOCK_ERR_NO_ERROR)
		{
				M2M_ERR("Error(%d):: socket recvfrom \n", ret);
		}
	}
	else
	{
		M2M_ERR("Error(%d):: Buffer is NULL or Buffer Length is 0 \n");
		ret = SOCK_ERR_INVALID;
	}
	
	return atwinc_socket_error_remap(ret);
}

static socket_error_t atwinc_get_local_addr(const struct socket *sock, struct socket_addr *address)
{
    M2M_INFO("atwinc_get_local_addr:: Not implmented\r\n");
	
	return SOCKET_ERROR_UNIMPLEMENTED;
}

static socket_error_t atwinc_get_remote_addr(const struct socket *sock, struct socket_addr *address)
{
    tWincSock *wincSock = NULL;

	if (!sock || !sock->impl || !address)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)sock->impl;

	socket_addr_set_ipv4_addr(address, wincSock->remoteIp);

	M2M_INFO("atwinc_get_remote_addr:: remote Ip : 0x%08X \n", wincSock->remoteIp);
	
	return SOCKET_ERROR_NONE;
}

static socket_error_t atwinc_get_local_port(const struct socket *sock, uint16_t *port)
{
    M2M_INFO("atwinc_get_local_port:: Not implmented \n");
	
	return SOCKET_ERROR_UNIMPLEMENTED;
}

static socket_error_t atwinc_get_remote_port(const struct socket *sock, uint16_t *port)
{
	tWincSock *wincSock = NULL;

	if (!sock || !sock->impl || !port)
		return SOCKET_ERROR_NULL_PTR;

	wincSock = (tWincSock *)sock->impl;
	*port = wincSock->remotePort;

	M2M_INFO("atwinc_get_remote_port:: remote port : %d \n", wincSock->remotePort);
	
	return SOCKET_ERROR_NONE;
}

static socket_error_t atwinc_socket_reject(struct socket *sock)
{
	M2M_INFO("atwinc_socket_reject:: Not implmented \n");

	return SOCKET_ERROR_UNIMPLEMENTED;
}

static socket_error_t atwinc_socket_set_option(struct socket *sock, const socket_proto_level_t level,
        const socket_option_type_t type, const void *option, const size_t optionSize)
{
	M2M_INFO("atwinc_socket_set_option:: Not implmented \n");
	
	return SOCKET_ERROR_UNIMPLEMENTED;
}

static socket_error_t atwinc_socket_get_option(struct socket *sock, const socket_proto_level_t level,
        const socket_option_type_t type, void *option, const size_t optionSize)
{
	M2M_INFO("atwinc_socket_get_option:: Not implmented \n");
	
	return SOCKET_ERROR_UNIMPLEMENTED;
}

const struct socket_api winc1500_socket_api = {
    .stack = SOCKET_STACK_ATWINC_IPV4,
    .version = SOCKET_ABSTRACTION_LAYER_VERSION,
    .init = atwinc_init,
    .create = atwinc_socket_create,
    .destroy = atwinc_socket_destroy,
    .close = atwinc_socket_close,
    .periodic_task = atwinc_socket_periodic_task,
    .periodic_interval = atwinc_socket_periodic_interval,
    .resolve = atwinc_socket_resolve,
    .connect = atwinc_socket_connect,
    .str2addr = atwinc_str2addr,
    .bind = atwinc_socket_bind,
    .start_listen = atwinc_start_listen,
    .stop_listen = atwinc_stop_listen,
    .accept = atwinc_socket_accept,
    .reject = atwinc_socket_reject,
    .send = atwinc_socket_send,
    .send_to = atwinc_socket_send_to,
    .recv = atwinc_socket_recv,
    .recv_from = atwinc_socket_recv_from,
    .set_option = atwinc_socket_set_option,
    .get_option = atwinc_socket_get_option,
    .is_connected = atwinc_socket_is_connected,
    .is_bound = atwinc_socket_is_bound,
    .get_local_addr = atwinc_get_local_addr,
    .get_remote_addr = atwinc_get_remote_addr,
    .get_local_port = atwinc_get_local_port,
    .get_remote_port = atwinc_get_remote_port,
    .accept_v2 = atwinc_socket_accept_v2,
};


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static void wifi_noti_cb(uint8_t u8MsgType, void *pvMsg)
{
	switch (u8MsgType) 
	{
		/* M2M_STA_CMD_BASE */
		case M2M_WIFI_RESP_CON_STATE_CHANGED:
		{
			tstrM2mWifiStateChanged *pstrWifiState = (tstrM2mWifiStateChanged *)pvMsg;
			if (pstrWifiState->u8CurrState == M2M_WIFI_CONNECTED)
			{
				//M2M_INFO("wifi_cb: [STA] M2M_WIFI_RESP_CON_STATE_CHANGED: CONNECTED\r\n");
				m2m_wifi_request_dhcp_client();
			}
			else if (pstrWifiState->u8CurrState == M2M_WIFI_DISCONNECTED)
			{
				M2M_INFO("wifi_cb: [STA] M2M_WIFI_RESP_CON_STATE_CHANGED: DISCONNECTED(%d) \n", pstrWifiState->u8ErrCode);
				m2m_wifi_connect((char*)gApSSId, strlen((const char*)gApSSId), gSecType, (void*)gApPass, M2M_WIFI_CH_ALL);
			}

			break;
		}

		case M2M_WIFI_REQ_DHCP_CONF:
		{
			uint8_t *pu8IPAddress = (uint8_t *)pvMsg;
			
			M2M_INFO("wifi_cb: [STA] M2M_WIFI_REQ_DHCP_CONF: IP is %u.%u.%u.%u \n", 
				pu8IPAddress[0], pu8IPAddress[1], pu8IPAddress[2], pu8IPAddress[3]);
			
			gWifiConnected = 1;
			gCbState = AT_WIFI_CONNECT;

			break;
		}
		
		case M2M_WIFI_REQ_DISCONNECT:
		{
			M2M_INFO("wifi_cb: [AP] M2M_WIFI_REQ_DISCONNECT \n");
			gWifiConnected = 0;
			gCbState = AT_STATE_UNKNOWN;
			break;
		}

		default:
		{
			break;
		}
	}
}

int32_t at_wifi_init(void)
{
	int8_t ret = M2M_SUCCESS;
	tstrWifiInitParam param;

	gCbState = AT_STATE_UNKNOWN;
	
	/* Initialize the BSP. */
	nm_bsp_init();

	/* Initialize WIFI parameters structure. */
	memset((uint8_t *)&param, 0, sizeof(tstrWifiInitParam));
	param.pfAppWifiCb = wifi_noti_cb;
	
	/* Initialize WINC1500 WIFI driver with data and status callbacks. */
	ret = m2m_wifi_init(&param);
	if (M2M_SUCCESS != ret)
	{
		M2M_ERR("m2m_wifi_init call error!(%d) \n", ret);
		return -1;
	}

	return ret;
}

int32_t at_wifi_connect(uint8_t secType, char* ssid, char* pass)
{
	int8_t ret = M2M_SUCCESS;
	socket_error_t err = SOCKET_ERROR_NONE;

	//M2M_INFO("WIFI Connection Info : Sec = %d, Id = %s, pw = %s\r\n", secType, ssid, pass);

	if (!ssid || !pass)
	{
		M2M_ERR("m2m_wifi_connect call error!: ssid or pass is NULL \n");
		return -1;
	}
	else
	{
		memcpy(gApSSId, ssid, strlen(ssid));
		memcpy(gApPass, pass, strlen(pass));
		gSecType = (uint8_t)secType;
	}

	/* Connect to router. */
	ret = m2m_wifi_connect((char *)ssid, strlen(ssid), secType, (void *)pass, M2M_WIFI_CH_ALL);
	if (ret != M2M_SUCCESS)
	{
		M2M_ERR("m2m_wifi_connect call error! \n");
		return -1;
	}

	winc_event_loop(AT_WIFI_CONNECT);

	at_sock_init();

	err = socket_register_stack(&winc1500_socket_api);
	if (err != SOCKET_ERROR_NONE)
	{
		M2M_ERR("at_sock_init:: Error, socket_register_stack(%d) \n", err);
	}

	return ret;
}

int32_t at_wifi_is_connected(void)
{
	return gWifiConnected;
}

void at_wifi_diconnect(void)
{
	int8_t ret = M2M_SUCCESS;
	
	ret = m2m_wifi_disconnect();
	if (ret != M2M_SUCCESS)
	{
		M2M_ERR("m2m_wifi_disconnect call error!\n");
	}
}

void at_wifi_deinit(void)
{
	m2m_wifi_deinit(NULL);
}

