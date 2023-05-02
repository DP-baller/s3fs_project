#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rc4.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <unistd.h>

// Function to print the correct usage of the program
void print_usage(char *prog_name) {
    fprintf(stderr, "Usage: %s input_file output_file {-e|-d} [-salt|-nosalt] key\n", prog_name);
}

int main(int argc, char *argv[]) {
    // Check if the correct number of arguments is provided
    if (argc != 6) {
        print_usage(argv[0]);
        return 1;
    }

    // Parse command line arguments
    const char *input_filename = argv[1];
    const char *output_filename = argv[2];
    int encrypt_mode = strcmp(argv[3], "-e") == 0;
    int decrypt_mode = strcmp(argv[3], "-d") == 0;
    int use_salt = strcmp(argv[4], "-salt") == 0;
    int no_salt = strcmp(argv[4], "-nosalt") == 0;
    const unsigned char *key_data = (const unsigned char *)argv[5];
    size_t key_data_len = strlen(argv[5]);

    // Validate mode and salt options
    if (!encrypt_mode && !decrypt_mode) {
        fprintf(stderr, "Invalid mode. Use -e for encryption or -d for decryption.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (!use_salt && !no_salt) {
        fprintf(stderr, "Invalid option. Use -salt or -nosalt.\n");
        print_usage(argv[0]);
        return 1;
    }

    // Open input and output files
    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file) {
        perror("Error opening input file");
        return 1;
    }

    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        perror("Error opening output file");
        fclose(input_file);
        return 1;
    }

    unsigned char salt[8];
    if (encrypt_mode && use_salt) {
        // Generate random salt for encryption
        if (!RAND_bytes(salt, 8)) {
            fprintf(stderr, "Error generating random salt\n");
            fclose(input_file);
            fclose(output_file);
            return 1;
        }
        // Write the salt header and salt to the output file
        fwrite("Salted__", 1, 8, output_file);
        fwrite(salt, 1, 8, output_file);
    } 
    else if (decrypt_mode && use_salt) {
        // Read the salt header and salt from the input file
        unsigned char salted[8];
        if (fread(salted, 1, 8, input_file) != 8 || memcmp(salted, "Salted__", 8) != 0) {
            fprintf(stderr, "Error reading salt from input file\n");
            fclose(input_file);
            fclose(output_file);
            return 1;
        }
        if (fread(salt, 1, 8, input_file) != 8) {
            fprintf(stderr, "Error reading salt from input file\n");
            fclose(input_file);
            fclose(output_file);
            return 1;
        }
    }

    // Create the key and initialization vector (IV) using the provided key data and salt (if applicable)
    const EVP_CIPHER *cipher = EVP_rc4();
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    EVP_BytesToKey(cipher, EVP_sha256(), use_salt ? salt : NULL, key_data, key_data_len, 1, key, iv);

    // Initialize the RC4 key structure with the derived key
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, EVP_CIPHER_key_length(cipher), key);

    // Get the system's page size and allocate the buffer
    long page_size = sysconf(_SC_PAGESIZE);
    unsigned char *buffer = (unsigned char *)malloc(page_size);
    size_t bytes_read;

    // Process the input file in chunks
    while ((bytes_read = fread(buffer, 1, page_size, input_file)) > 0) {
        // Encrypt or decrypt the buffer using RC4
        RC4(&rc4_key, bytes_read, buffer, buffer);
        // Write the processed buffer to the output file
        fwrite(buffer, 1, bytes_read, output_file);
    }

    // Free the buffer
    free(buffer);

    // Close the input and output files
    fclose(input_file);
    fclose(output_file);

    // Print a success message
    if (encrypt_mode)
        printf("File %s encrypted successfully to %s\n", input_filename, output_filename);
    else
        printf("File %s decrypted successfully to %s\n", input_filename, output_filename);

    return 0;
}

