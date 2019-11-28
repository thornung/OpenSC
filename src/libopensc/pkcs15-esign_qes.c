/**
 * PKCS15 emulation layer for GuD cards with eSign and QES application
 *
 * Copyright (C) 2019, Jozsef Dojcsak
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "common/compat_strlcpy.h"
#include "log.h"
#include "pkcs15.h"
#include "cards.h"
#include <stdlib.h>
#include <string.h>

typedef struct cdata_st {
	const char *label;
	int	    authority;
	const char *path;
	const char *id;
	int         obj_flags;
} cdata, *pcdata;

typedef struct pdata_st {
	const char *id;
	const char *label;
	const char *path;
	int         ref;
	int         type;
	unsigned int maxlen;
	unsigned int minlen;
	unsigned int storedlen;
	int         flags;	
	int         tries_left;
	const char  pad_char;
	int         obj_flags;
} pindata, *ppindata; 

typedef struct prdata_st {
	const char *id;
	const char *label;
	unsigned int modulus_len;
	int         usage;
	const char *path;
	int         ref;
	const char *auth_id;
	int         obj_flags;
} prdata, *pprdata;

typedef struct container_st {
	const char *id;
	const pcdata certdata;
	const ppindata pindata;
	const pprdata prdata;
} container;

#define USAGE_NONREP	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
#define USAGE_KE	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP
#define USAGE_AUT	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP  | \
			SC_PKCS15_PRKEY_USAGE_SIGN

static const char name_ESIGN[] = "eSIGN";
static const char EF_TokenInfo[] = "5032";

//static const unsigned char aid_ESIGN[] = {0xA0, 0x00, 0x00, 0x02, 0x45, 0x53, 0x69, 0x67, 0x6E};
//static const unsigned char aid_QES[] = {0xD2, 0x76, 0x00, 0x00, 0x66, 0x01};
static const unsigned char aid_CIA_ESIGN[] = {0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xA0, 0x00, 0x00, 0x02, 0x45, 0x53, 0x69, 0x67, 0x6E};
//static const unsigned char aid_CIA_QES[] = {0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xD2, 0x76, 0x00, 0x00, 0x66, 0x01};

static int read_tokeninfo(sc_pkcs15_card_t *p15card, struct sc_file **pfile_tokeninfo, struct sc_pkcs15_tokeninfo **ptokeninfo) {
    int r;
    unsigned char *tokeninfo_content = NULL;
    sc_path_t path;

    sc_path_set(&path, SC_PATH_TYPE_DF_NAME, aid_CIA_ESIGN, sizeof(aid_CIA_ESIGN), 0, 0);
    r = sc_select_file(p15card->card, &path, NULL);
    if (SC_SUCCESS != r) return r;

    sc_format_path(EF_TokenInfo, &path);
    r = sc_select_file(p15card->card, &path, pfile_tokeninfo);
    if (SC_SUCCESS != r) return r;

    tokeninfo_content = malloc((*pfile_tokeninfo)->size);
    if (tokeninfo_content != NULL) {
        r = sc_read_binary(p15card->card, 0, tokeninfo_content, (*pfile_tokeninfo)->size, 0);
        if (r >= 0) {
            r = sc_pkcs15_parse_tokeninfo(p15card->card->ctx, *ptokeninfo, tokeninfo_content, r);
            if (r == SC_SUCCESS) {
                if ((*ptokeninfo)->label != NULL && 0 == strcmp(name_ESIGN, (*ptokeninfo)->label)) {
                    r = SC_SUCCESS;
                } else {
                    r = SC_ERROR_WRONG_CARD;
                }
            }
        }
        free(tokeninfo_content);
    } else {
        r = SC_ERROR_OUT_OF_MEMORY;
    }

    return r;
}

static int get_cert_len(sc_card_t *card, sc_path_t *path)
{
	int r;
	u8  buf[8];

	r = sc_select_file(card, path, NULL);
	if (r < 0)
		return 0;
	r = sc_read_binary(card, 0, buf, sizeof(buf), 0);
	if (r < 0)	
		return 0;
	if (buf[0] != 0x30 || buf[1] != 0x82)
		return 0;
	path->index = 0;
	path->count = ((((size_t) buf[2]) << 8) | buf[3]) + 4;
	return 1;
} 

int sc_pkcs15emu_esign_qes_init(sc_pkcs15_card_t *p15card) {
	int    r;
    unsigned int i;

	cdata auth_cert = { "C.CH.AUT", 0, "3F00060843F1", "1", 0 };
	cdata encr_cert = { "C.CH.ENC", 0, "3F0006084301", "2", 0 };
	cdata sign_cert = { "C.CH.QES", 0, "3F0006044301", "3", 0 };
	cdata auth_root_cert = { "C.RootCA_Auth", 1, "3F00060843F0", "4", 0 };
	cdata encr_root_cert = { "C.RootCA_Enc", 1, "3F0006084300", "5", 0 };
	cdata sign_root_cert = { "C.RootCA_QES", 1, "3F0006044300", "6", 0 };
	prdata auth_key = { "1", "PrK.CH.AUT", 2048, USAGE_AUT, "3F0006080F01", 0x81, "1", SC_PKCS15_CO_FLAG_PRIVATE };
	prdata encr_key = { "2", "PrK.CH.ENC", 2048, USAGE_KE, "3F0006080F02", 0x83, "1", SC_PKCS15_CO_FLAG_PRIVATE };
	prdata sign_key = { "3", "PrK.CH.QES", 2048, SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION, "3F0006040F01", 0x84, "2", SC_PKCS15_CO_FLAG_PRIVATE };
	prdata sign3072_key = { "3", "PrK.CH.QES", 3072, SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION, "3F0006040F01", 0x84, "2", SC_PKCS15_CO_FLAG_PRIVATE };
	pindata auth_pin = { "1", "Auth.PIN", "3F00", 0x01, SC_PKCS15_PIN_TYPE_UTF8, 16, 6, 0,
		SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_CASE_SENSITIVE,
		-1, 0x00, SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE };
	pindata sign_pin = { "2", "Sign.PIN", "3F000604", 0x81,  SC_PKCS15_PIN_TYPE_UTF8, 16, 6, 0,
		SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_CONFIDENTIALITY_PROTECTED | SC_PKCS15_PIN_FLAG_LOCAL,
		-1, 0x00, SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE };

	sc_card_t *card = p15card->card;
	const container containers[] = {
		{ "1", &auth_cert, &auth_pin, &auth_key },
		{ "2", &encr_cert, &auth_pin, &encr_key },
		{ "3", &sign_cert, &sign_pin, (card->type == SC_CARD_TYPE_STARCOS_V3_5 ? &sign3072_key : &sign_key) },
		{ "4", &auth_root_cert, 0, 0 },
		{ "5", &encr_root_cert, 0, 0 },
		{ "6", &sign_root_cert, 0, 0 },
	};

	ppindata installed_pins[2];
	int installed_pin_count = 0;

	/* enumerate containers */
	for( i=0; i<sizeof(containers)/sizeof(container); i++) {
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object    cert_obj;

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj,  0, sizeof(cert_obj));

		sc_pkcs15_format_id(containers[i].id, &cert_info.id);
		cert_info.authority = containers[i].certdata->authority;
		sc_format_path(containers[i].certdata->path, &cert_info.path);
		if (!get_cert_len(card, &cert_info.path))
			/* skip errors */
			continue;

		strlcpy(cert_obj.label, containers[i].certdata->label, sizeof(cert_obj.label));
		cert_obj.flags = containers[i].certdata->obj_flags;

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;

		if (containers[i].pindata != 0) {
			// check if pin is installed.
			int j;
			int is_pin_installed = 0;
			for (j = 0; j < installed_pin_count; j++) {
				if (installed_pins[j] == containers[i].pindata) {
					is_pin_installed = 1;
					break;
				}
			}

			if (!is_pin_installed) {
				struct sc_pkcs15_auth_info pin_info;
				struct sc_pkcs15_object   pin_obj;
				int reference = containers[i].pindata->ref;

				installed_pins[installed_pin_count++] = containers[i].pindata;

				if (reference == 0x01 && card->type == SC_CARD_TYPE_STARCOS_V3_5) {
					reference = 0x06;
				}

				memset(&pin_info, 0, sizeof(pin_info));
				memset(&pin_obj, 0, sizeof(pin_obj));

				sc_pkcs15_format_id(containers[i].pindata->id, &pin_info.auth_id);
				pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
				pin_info.attrs.pin.reference = reference;
				pin_info.attrs.pin.flags = containers[i].pindata->flags;
				pin_info.attrs.pin.type = containers[i].pindata->type;
				pin_info.attrs.pin.min_length = containers[i].pindata->minlen;
				pin_info.attrs.pin.stored_length = containers[i].pindata->storedlen;
				pin_info.attrs.pin.max_length = containers[i].pindata->maxlen;
				pin_info.attrs.pin.pad_char = containers[i].pindata->pad_char;
				if (containers[i].pindata->path != NULL) sc_format_path(containers[i].pindata->path, &pin_info.path);
				pin_info.tries_left = -1;

				strlcpy(pin_obj.label, containers[i].pindata->label, sizeof(pin_obj.label));
				pin_obj.flags = containers[i].pindata->obj_flags;

				r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
				if (r < 0)
					return SC_ERROR_INTERNAL;
			}
		}

		if (containers[i].prdata != 0) {
			struct sc_pkcs15_prkey_info prkey_info;
			struct sc_pkcs15_object     prkey_obj;
			int modulus_len = containers[i].prdata->modulus_len;
			memset(&prkey_info, 0, sizeof(prkey_info));
			memset(&prkey_obj, 0, sizeof(prkey_obj));

			sc_pkcs15_format_id(containers[i].id, &prkey_info.id);
			prkey_info.usage = containers[i].prdata->usage;
			prkey_info.native = 1;
			prkey_info.key_reference = containers[i].prdata->ref;
			prkey_info.modulus_length = modulus_len;
			sc_format_path(containers[i].prdata->path, &prkey_info.path);

			strlcpy(prkey_obj.label, containers[i].prdata->label, sizeof(prkey_obj.label));
			prkey_obj.flags = containers[i].prdata->obj_flags;
			if (containers[i].prdata->auth_id)
				sc_pkcs15_format_id(containers[i].prdata->auth_id, &prkey_obj.auth_id);

			r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
			if (r < 0)
				return SC_ERROR_INTERNAL;
		}
	}
	
	return SC_SUCCESS;
}

int sc_pkcs15emu_esign_qes_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid) {
    int r;
    size_t aid_esign_len = sizeof(aid_CIA_ESIGN);
    struct sc_pkcs15_tokeninfo *tokeninfo = NULL;
    struct sc_file *file_tokeninfo = NULL;

    SC_FUNC_CALLED(p15card->card->ctx, 1);

    if (!p15card || ! p15card->card) return SC_ERROR_INVALID_ARGUMENTS;

    if ((aid && (aid->len != aid_esign_len || 0 != memcmp(aid->value, aid_CIA_ESIGN, aid_esign_len)))) return SC_ERROR_WRONG_CARD;

    if (!p15card->tokeninfo || !p15card->tokeninfo->profile_indication.name || 0 != strcmp(name_ESIGN, p15card->tokeninfo->profile_indication.name)) {
        tokeninfo = sc_pkcs15_tokeninfo_new();
        if (!tokeninfo) return SC_ERROR_OUT_OF_MEMORY;

        r = read_tokeninfo(p15card, &file_tokeninfo, &tokeninfo);
        if ( SC_SUCCESS != r ) {
            sc_file_free(file_tokeninfo);
            sc_pkcs15_free_tokeninfo(tokeninfo);
            return r;
        }
    }

    r = sc_pkcs15emu_esign_qes_init(p15card);
    if (SC_SUCCESS == r) {
        sc_serial_number_t serial;
        sc_pkcs15_free_tokeninfo(p15card->tokeninfo);
        sc_file_free(p15card->file_tokeninfo);

        p15card->tokeninfo = tokeninfo;
        p15card->file_tokeninfo = file_tokeninfo;
        tokeninfo = NULL;
        file_tokeninfo = NULL;

        /* get the card serial number */
        if (!p15card->tokeninfo->serial_number
                && SC_SUCCESS == sc_card_ctl(p15card->card, SC_CARDCTL_GET_SERIALNR, &serial)) {
            char serial_hex[SC_MAX_SERIALNR*2+2];
            sc_bin_to_hex(serial.value, serial.len , serial_hex, sizeof serial_hex, 0);
            p15card->tokeninfo->serial_number = strdup(serial_hex);
        }
    } else {
        sc_file_free(file_tokeninfo);
        sc_pkcs15_free_tokeninfo(tokeninfo);
    }

    return r;
}
