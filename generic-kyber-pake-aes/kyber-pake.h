#include <stdint.h>
#include "params.h"
#include "kem.h"
void pake_a0(
	const unsigned char *pw, 
	const uint8_t *ssid, 
	uint8_t *send_a0,
	uint8_t *pk, 
	uint8_t *sk);


void pake_b0(
	const unsigned char *pw, 
	const uint8_t *ssid,
	const unsigned char *a_id,
	const unsigned char *b_id,
	uint8_t *epk, 
	uint8_t *send_b0, 
	uint8_t *ct,
	uint8_t *k,
	uint8_t *auth_b);

void pake_a1(
	const unsigned char *pw,
	uint8_t *sk, 
	uint8_t *epk, 
	uint8_t *send_b0, 
	const uint8_t *ssid,
	const unsigned char *a_id,
	const unsigned char *b_id, 
	uint8_t *ct,
	uint8_t *key_a);

void pake_b1(
	const uint8_t *ssid,
	const unsigned char *a_id,
	const unsigned char *b_id,
	uint8_t *send_a0,
	uint8_t *ct,
	uint8_t *auth_b,
	uint8_t *k,
	uint8_t *key_b);

void printData(const uint8_t *data, size_t dataSize);