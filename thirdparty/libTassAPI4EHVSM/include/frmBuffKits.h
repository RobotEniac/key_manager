/**
* Copyright (C) 2021 TASS
* @file frmBuffKits.h
* @brief  一些关于字节序和内存的处理功能
* @details Memory and byte processing is supported
* @author Kangying
* @version 2.0.0
* @date 2021/09/02
* Change History :
* <Date>     | <Version>  | <Author>       | <Description>
*---------------------------------------------------------------------------
* 2021/09/02 | 2.0.0      | Kangying       | Create file
*---------------------------------------------------------------------------
*/

#ifndef TASSAPIFRAME_INCLUDE_FRMBUFFKITS_H
#define TASSAPIFRAME_INCLUDE_FRMBUFFKITS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include "frmTypes.h"

#if _MSC_VER
#define STDCALL_ __stdcall
#else
#define STDCALL_
#endif

#define frmMalloc(memory, type, size)    if( memory==NULL ){                    \
                                            memory = (type *)malloc(size);  \
                                        }else {                                 \
                                            free(memory);                       \
                                            memory = (type *)malloc(size);  \
                                        }

#define frmFree(Memory)                  if(Memory != NULL){                    \
                                            free(Memory);                       \
                                            Memory = NULL;                      \
                                                                                }

	/*内存缓冲区置0*/
#define frmB_ZERO(buf, length) memset(buf, 0, length)

#define REVERSE16(x)                            \
       ((x&0x00ff) << 8)                        \
      |((x&0xff00) >> 8)

#define REVERSE32(x)                            \
       ((x&0x000000ff) << 24)                   \
      |((x&0x0000ff00) << 8)                    \
      |((x&0x00ff0000) >> 8)                    \
      |((x&0xff000000) >> 24)

#define REVERSE64(x)                            \
       ((x&0x00000000000000ffUL) << 56)         \
      |((x&0x000000000000ff00UL) << 40)         \
      |((x&0x0000000000ff0000UL) << 24)         \
      |((x&0x00000000ff000000UL) << 8)          \
      |((x&0x000000ff00000000UL) >> 8)          \
      |((x&0x0000ff0000000000UL) >> 24)         \
      |((x&0x00ff000000000000UL) >> 40)         \
      |((x&0xff00000000000000UL) >> 56)         \

	/**
	* @brief   以大端字节序从缓冲区读取一个64bits整型值
	*
	* @param   p   缓冲区指针首地址
	*
	* @return  64bits整型值
	*/
#define DATA_READ_UINT64_BE(p)                  \
      ((FRM_UINT64)(p[0] << 56)                 \
      |(FRM_UINT64)(p[1] << 48)                 \
      |(FRM_UINT64)(p[2] << 40)                 \
      |(FRM_UINT64)(p[3] << 32)                 \
      |(FRM_UINT64)(p[4] << 24)                 \
      |(FRM_UINT64)(p[5] << 16)                 \
      |(FRM_UINT64)(p[6] << 8)                  \
      |(FRM_UINT64)(p[7]))

	/**
	* @brief   以大端字节序将一个64bits整型值写入缓冲区
	*
	* @param   p   缓冲区指针首地址
	* @param   i   64bits整型值
	*/
#define DATA_WRITE_UINT64_BE(p, i)              \
  do {                                          \
    p[0] = (FRM_UINT8)((i >> 56) & 0xff);       \
    p[1] = (FRM_UINT8)((i >> 48) & 0xff);       \
    p[2] = (FRM_UINT8)((i >> 40) & 0xff);       \
    p[3] = (FRM_UINT8)((i >> 32) & 0xff);       \
    p[4] = (FRM_UINT8)((i >> 24) & 0xff);       \
    p[5] = (FRM_UINT8)((i >> 16) & 0xff);       \
    p[6] = (FRM_UINT8)((i >> 8 ) & 0xff);       \
    p[7] = (FRM_UINT8)(i         & 0xff);       \
    } while(0)

	/**
	* @brief   以大端字节序从缓冲区读取一个32bits整型值
	*
	* @param   p   缓冲区指针首地址
	*
	* @return  32bits整型值
	*/
#define DATA_READ_UINT32_BE(p)                  \
      ((FRM_UINT32)(p[0] << 24)                 \
      |(FRM_UINT32)(p[1] << 16)                 \
      |(FRM_UINT32)(p[2] << 8)                  \
      |(FRM_UINT32)(p[3]))

	/**
	* @brief   以大端字节序将一个32bits整型值写入缓冲区
	*
	* @param   p   缓冲区指针首地址
	* @param   i   32bits整型值
	*/
#define DATA_WRITE_UINT32_BE(p, i)              \
  do {                                          \
    p[0] = (FRM_UINT8)((i >> 24) & 0xff);       \
    p[1] = (FRM_UINT8)((i >> 16) & 0xff);       \
    p[2] = (FRM_UINT8)((i >> 8 ) & 0xff);       \
    p[3] = (FRM_UINT8)(i         & 0xff);       \
    } while(0)

	/**
	* @brief   以大端字节序从缓冲区读取一个16bits整型值
	*
	* @param   p   缓冲区指针首地址
	*
	* @return  16bits整型值
	*/
#define DATA_READ_UINT16_BE(p)                  \
      ((FRM_UINT32)(p[0] << 8)                  \
      |(FRM_UINT32)(p[1]))

	/**
	* @brief   以大端字节序将一个16bits整型值写入缓冲区
	*
	* @param   p   缓冲区指针首地址
	* @param   i   16bits整型值
	*/
#define DATA_WRITE_UINT16_BE(p, i)              \
  do {                                          \
    p[0] = (FRM_UINT8)(((i) >> 8 ) & 0xff);       \
    p[1] = (FRM_UINT8)((i)         & 0xff);       \
    } while(0)

	/**
	* @brief   以小端字节序从缓冲区读取一个64bits整型值
	*
	* @param   p   缓冲区指针首地址
	*
	* @return  64bits整型值
	*/
#define DATA_READ_UINT64_LE(p)                  \
      ((FRM_UINT64)(p[7] << 56)                 \
      |(FRM_UINT64)(p[6] << 48)                 \
      |(FRM_UINT64)(p[5] << 40)                 \
      |(FRM_UINT64)(p[4] << 32)                 \
      |(FRM_UINT64)(p[3] << 24)                 \
      |(FRM_UINT64)(p[2] << 16)                 \
      |(FRM_UINT64)(p[1] << 8)                  \
      |(FRM_UINT64)(p[0]))

	/**
	* @brief   以小端字节序将一个64bits整型值写入缓冲区
	*
	* @param   p   缓冲区指针首地址
	* @param   i   64bits整型值
	*/
#define DATA_WRITE_UINT64_LE(p, i)              \
  do {                                          \
    p[7] = (FRM_UINT8)((i >> 56) & 0xff);       \
    p[6] = (FRM_UINT8)((i >> 48) & 0xff);       \
    p[5] = (FRM_UINT8)((i >> 40) & 0xff);       \
    p[4] = (FRM_UINT8)((i >> 32) & 0xff);       \
    p[3] = (FRM_UINT8)((i >> 24) & 0xff);       \
    p[2] = (FRM_UINT8)((i >> 16) & 0xff);       \
    p[1] = (FRM_UINT8)((i >> 8 ) & 0xff);       \
    p[0] = (FRM_UINT8)(i         & 0xff);       \
    } while(0)

	/**
	* @brief   以小端字节序从缓冲区读取一个32bits整型值
	*
	* @param   p   缓冲区指针首地址
	*
	* @return  32bits整型值
	*/
#define DATA_READ_UINT32_LE(p)                  \
      ((FRM_UINT32)(p[3] << 24)                 \
      |(FRM_UINT32)(p[2] << 16)                 \
      |(FRM_UINT32)(p[1] << 8)                  \
      |(FRM_UINT32)(p[0]))


	/**
	* @brief   以小端字节序将一个32bit整型值写入缓冲区
	*
	* @param   p   缓冲区指针首地址
	* @param   i   32bits整型值
	*/
#define DATA_WRITE_UINT32_LE(p, i)              \
  do {                                          \
    p[3] = (FRM_UINT8)((i >> 24) & 0xff);       \
    p[2] = (FRM_UINT8)((i >> 16) & 0xff);       \
    p[1] = (FRM_UINT8)((i >> 8 ) & 0xff);       \
    p[0] = (FRM_UINT8)(i         & 0xff);       \
    } while(0)

	/**
	* @brief   以小端字节序从缓冲区读取一个16bits整型值
	*
	* @param   p    缓冲区指针首地址
	*
	* @return  16bits整型值
	*/
#define DATA_READ_UINT16_LE(p)                  \
      ((FRM_UINT32)(p[1] << 8)                  \
      |(FRM_UINT32)(p[0]))

	/**
	* @brief   以小端字节序将一个16bits整型值写入缓冲区
	*
	* @param   p   缓冲区指针首地址
	* @param   i   16bits整型值
	*/
#define DATA_WRITE_UINT16_LE(p, i)              \
  do {                                          \
    p[1] = (FRM_UINT8)((i >> 8 ) & 0xff);       \
    p[0] = (FRM_UINT8)(i         & 0xff);       \
    } while(0)



	/**
	* @brief   判断当前环境是否大端字节序
	*
	* @return  0表否,1表是
	*/
	LIBFRM_EXPORT FRM_BOOL IsBigEndian();

	/**
	* @brief   判断当前环境是否小端字节序
	*
	* @return  0表否,1表是
	*/
	LIBFRM_EXPORT FRM_BOOL IsLittleEndian();

	/**
	* @brief   将字符串解析为整型数值
	*
	* @param   s       [in]    字符串指针
	* @param   len     [in]    最大长度
	* @param   radix   [in]    进制符（2，4，8，10，16）
	*
	* @return  返回解析结果
	*/
	LIBFRM_EXPORT FRM_INT32 parseInt(FRM_INT8_PTR s, FRM_INT32 len, FRM_INT32 radix);

	/**
	* @brief   二进制数据进行HEX字符串编码
	*
	* @param   pucInBuff
	* @param   nInLength
	* @param   pcOutHexString
	*
	* @return
	*/
	LIBFRM_EXPORT FRM_INT32 HexBinEncode(FRM_UINT8_PTR pucInBuff, FRM_INT32 nInLength, FRM_INT8_PTR pcOutHexString);

	/**
	* @brief   HEX字符串解码为二进制数据
	*
	* @param   szInHexString
	* @param   pucOutBuf
	* @param   nOutLength
	*
	* @return
	*/
	LIBFRM_EXPORT FRM_INT32 HexBinDecode(FRM_INT8_PTR szInHexString, FRM_UINT8_PTR pucOutBuf, FRM_INT32_PTR pnOutLength);

	/**
	 * @brief   二进制流数据按位异或运算
	 *
	 * @param   pucBuff1        [in]    数据1缓冲区指针
	 * @param   pucBuff2        [in]    数据2缓冲区指针
	 * @param   nLength         [in]    异或运算字节数
	 * @param   pucResult       [out]   输出数据缓冲区指针
	 */
	LIBFRM_EXPORT FRM_VOID BytesXor(FRM_UINT8_PTR pucBuff1, FRM_UINT8_PTR pucBuff2, FRM_INT32 nLength, FRM_UINT8_PTR pucResult);

	/**
	 * @brief   二进制流数据按位取反运算
	 *
	 * @param   pucBuff         [in]    输入数据缓冲区指针
	 * @param   nLength         [in]    运算数据长度
	 * @param   pucResult       [out]   输出数据缓冲区指针
	 */
	LIBFRM_EXPORT FRM_VOID BytesNot(FRM_UINT8_PTR pucBuff, FRM_INT32 nLength, FRM_UINT8_PTR pucResult);

	/**
	 * @brief	字符串转换为大写格式
	 *
	 * @param	szString		[i/o]	转换的字符串
	 */
	LIBFRM_EXPORT FRM_VOID StringToUpper(FRM_INT8_PTR szString);

	/**
	* @brief	字符串转换为小写格式
	*
	* @param	szString		[i/o]	转换的字符串
	*/
	LIBFRM_EXPORT FRM_VOID stringToLower(FRM_INT8_PTR szString);

#ifdef __cplusplus
}
#endif
#endif /*TASSAPIFRAME_INCLUDE_FRMBUFFKITS_H*/
