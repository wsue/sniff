/*
 * =====================================================================================
 *
 *       Filename:  sniff_parser.h
 *
 *    Description:  
 *
 *
 * =====================================================================================
 */
#ifndef SNIFF_PARSER_H_
#define SNIFF_PARSER_H_

#define MAX_PARSER_NUM      32

typedef int (*SNIFFPARSER_PARSE_CALLBACK)(void *param,const struct EthFrameInfo *pEthFrame);
typedef int (*SNIFFPARSER_RELEASE_CALLBACK)(void *param);

int SnifParser_Init();
int SniffParser_Register(SNIFFPARSER_RELEASE_CALLBACK release,SNIFFPARSER_PARSE_CALLBACK parser, void *param);
int SnifParser_Exec(struct EthFrameInfo *pEthFrame);
void SnifParser_ResetShow();
void SnifParser_Show();
int SniffParser_Release();

#endif


