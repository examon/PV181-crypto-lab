/* Tomas Meszaros - 422336
 *
 * Generate and print RSA parameters
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#define SPACE "\t"

static void print_head(FILE * out, const char *txt, unsigned int size, int cprint)
{
	unsigned i;
	char *p, *ntxt;

	if (cprint != 0) {
		if (size > 0)
			asprintf(&ntxt, "const unsigned char %s[%u] =",
				 txt, size);
		else
			asprintf(&ntxt, "const unsigned char %s[] =\n",
				 txt);

		p = strstr(ntxt, "char");
		p += 5;

		for (i = 0; i < strlen(txt); i++)
			if (p[i] == ' ')
				p[i] = '_';

		fprintf(out, "%s", ntxt);
		free(ntxt);

		return;
	}
	fprintf(out, "%s:", txt);
}


static void
print_hex_datum(FILE * outfile, gnutls_datum_t * dat, int cprint)
{
	unsigned int j;

	if (cprint != 0) {
		fprintf(outfile, "\n" SPACE "\"");
		for (j = 0; j < dat->size; j++) {
			fprintf(outfile, "\\x%.2x",
				(unsigned char) dat->data[j]);
			if ((j + 1) % 16 == 0) {
				fprintf(outfile, "\"\n" SPACE "\"");
			}
		}
		fprintf(outfile, "\";\n\n");

		return;
	}

	fprintf(outfile, "\n" SPACE);
	for (j = 0; j < dat->size; j++) {
		if ((j + 1) % 16 == 0) {
			fprintf(outfile, "%.2x", (unsigned char) dat->data[j]);
			fprintf(outfile, "\n" SPACE);
		} else {
			fprintf(outfile, "%.2x:", (unsigned char) dat->data[j]);
		}
	}
	fprintf(outfile, "\n\n");
}

void
print_rsa_pkey(FILE * outfile, gnutls_datum_t * m, gnutls_datum_t * e,
	       gnutls_datum_t * d, gnutls_datum_t * p, gnutls_datum_t * q,
	       gnutls_datum_t * u, gnutls_datum_t * exp1,
	       gnutls_datum_t * exp2, int cprint)
{
	print_head(outfile, "modulus", m->size, cprint);
	print_hex_datum(outfile, m, cprint);
	print_head(outfile, "public exponent", e->size, cprint);
	print_hex_datum(outfile, e, cprint);
	if (d) {
		print_head(outfile, "private exponent", d->size, cprint);
		print_hex_datum(outfile, d, cprint);
		print_head(outfile, "prime1", p->size, cprint);
		print_hex_datum(outfile, p, cprint);
		print_head(outfile, "prime2", q->size, cprint);
		print_hex_datum(outfile, q, cprint);
		print_head(outfile, "coefficient", u->size, cprint);
		print_hex_datum(outfile, u, cprint);
		if (exp1 && exp2) {
			print_head(outfile, "exp1", exp1->size, cprint);
			print_hex_datum(outfile, exp1, cprint);
			print_head(outfile, "exp2", exp2->size, cprint);
			print_hex_datum(outfile, exp2, cprint);
		}
	}
}

int main(void) {
	gnutls_privkey_t pk;
	if (gnutls_privkey_init(&pk) != 0)
		return -1;

	gnutls_privkey_generate(pk, 1, 1024, 0);
	gnutls_x509_privkey_t key;
	if (gnutls_privkey_export_x509(pk, &key) != 0)
		return -2;

	gnutls_datum_t m, e, d, p, q, u, exp1, exp2;
	int ret = gnutls_x509_privkey_export_rsa_raw2(key, &m, &e, &d, &p, &q, &u, &exp1, &exp2);
	if (ret < 0)
		return -100;
	print_rsa_pkey(stdout, &m, &e, &d, &p, &q, &u, &exp1, &exp2, 1);

	return 0;
}
