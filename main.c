// #define NDEBUG


#include <stdio.h>
#include <assert.h>


#define uc unsigned char


void* xor_enc_dec_rypt(
	void* data, size_t data_size,
	void* pass_phrase, size_t pass_phrase_size
) {
	assert(data != NULL && pass_phrase != NULL);

	for (size_t i = 0, j = 0; i < data_size; ++i)
	{
		((uc*)data)[i] ^= ((uc*)pass_phrase)[j++];
		if (j + 1 == pass_phrase_size) j ^= j;
	}

	return data;
}


void print_bytes(void* data, size_t size)
{
	printf("data: {");
	for (size_t i = 0; i < size; ++i)
	{
		printf("0x%.2X%s", ((uc*)data)[i], i + 1 < size ? ", " : "}\n");
	}
}


int main(int argc, const char** argv)
{
	char my_secret_text[] = "i known who you are!";
	size_t size_my_secret_text = sizeof(my_secret_text);

	uc pass[9] = { 0x32, 0x52, 0xF1, 0xEE, 0x1B, 0xBB, 0x12, 0xCC, 0xD7 };
	size_t size_pass = sizeof(pass);

	printf("before encryption: ");
	print_bytes(my_secret_text, size_my_secret_text);
	printf("pass phrase: ");
	print_bytes(pass, size_pass);
	putc('\n', stdout);

	xor_enc_dec_rypt(my_secret_text, size_my_secret_text,
		pass, size_pass);

	printf("after encryption: ");
	print_bytes(my_secret_text, size_my_secret_text);
	putc('\n', stdout);

	xor_enc_dec_rypt(my_secret_text, size_my_secret_text,
		pass, size_pass);

	printf("after decryption: ");
	print_bytes(my_secret_text, size_my_secret_text);
	putc('\n', stdout);

	printf("decrypted string: %s\n", my_secret_text);

	return 0;
}


/*
output:

before encryption: data: {0x69, 0x20, 0x6B, 0x6E, 0x6F, 0x77, 0x6E, 0x20, 0x77, 0x68, 0x6F, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x61, 0x72, 0x65, 0x21, 0x0}
pass phrase: data: {0x32, 0x52, 0xF1, 0xEE, 0x1B, 0xBB, 0x12, 0xCC, 0xD7}

after encryption: data: {0x5B, 0x72, 0x9A, 0x80, 0x74, 0xCC, 0x7C, 0xEC, 0x45, 0x3A, 0x9E, 0xCE, 0x62, 0xD4, 0x67, 0xEC, 0x53, 0x20, 0x94, 0xCF, 0x1B}

after decryption: data: {0x69, 0x20, 0x6B, 0x6E, 0x6F, 0x77, 0x6E, 0x20, 0x77, 0x68, 0x6F, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x61, 0x72, 0x65, 0x21, 0x0}

decrypted string: i known who you are!
*/
