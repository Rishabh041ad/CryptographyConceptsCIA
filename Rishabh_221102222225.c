#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX 1024

// Caesar Cipher
void caesar(char *in, char *out, int shift) {
    for (int i = 0; in[i]; i++) {
        if (isalpha(in[i])) {
            char base = isupper(in[i]) ? 'A' : 'a';
            out[i] = (in[i] - base + shift + 26) % 26 + base;
        } else {
            out[i] = in[i];
        }
    }
    out[strlen(in)] = '\0';
}

// Atbash Cipher
void atbash(char *in, char *out) {
    for (int i = 0; in[i]; i++) {
        if (isalpha(in[i])) {
            char base = isupper(in[i]) ? 'A' : 'a';
            out[i] = base + (25 - (in[i] - base));
        } else {
            out[i] = in[i];
        }
    }
    out[strlen(in)] = '\0';
}

// Affine Cipher Helpers
int modInverse(int a, int m) {
    a %= m;
    for (int x = 1; x < m; x++)
        if ((a * x) % m == 1)
            return x;
    return -1;
}

void affine(char *in, char *out, int a, int b, int decrypt) {
    int a_inv = modInverse(a, 26);
    if (decrypt && a_inv == -1) {
        strcpy(out, "Error: 'a' does not have a modular inverse for decryption.");
        return;
    }
    for (int i = 0; in[i]; i++) {
        if (isalpha(in[i])) {
            char base = isupper(in[i]) ? 'A' : 'a';
            int x = in[i] - base;
            out[i] = decrypt ? (a_inv * (x - b + 26)) % 26 + base : (a * x + b) % 26 + base;
        } else {
            out[i] = in[i];
        }
    }
    out[strlen(in)] = '\0';
}

// Vigenere, Gronsfeld, Autoclave Ciphers
void polySub(char *in, char *out, char *key, int decrypt, int isNumeric, int autoMode) {
    char fullKey[MAX];
    if (autoMode && !decrypt) {
        strcpy(fullKey, key);
        strncat(fullKey, in, MAX - strlen(key) - 1);
    }

    int j = 0, klen = strlen(key);
    for (int i = 0; in[i]; i++) {
        if (isalpha(in[i])) {
            int shift = isNumeric ? key[j % klen] - '0' : tolower(autoMode ? fullKey[i] : key[j % klen]) - 'a';
            if (decrypt) shift = 26 - shift;
            char base = isupper(in[i]) ? 'A' : 'a';
            out[i] = (in[i] - base + shift + 26) % 26 + base;
            j++;
        } else {
            out[i] = in[i];
        }
    }
    out[strlen(in)] = '\0';
}

// Beaufort Cipher
void beaufort(char *in, char *out, char *key) {
    int klen = strlen(key);
    for (int i = 0, j = 0; in[i]; i++) {
        if (isalpha(in[i])) {
            char base = isupper(in[i]) ? 'A' : 'a';
            int k = tolower(key[j % klen]) - 'a';
            out[i] = (26 + k - (tolower(in[i]) - 'a')) % 26 + base;
            j++;
        } else {
            out[i] = in[i];
        }
    }
    out[strlen(in)] = '\0';
}

// NGram Cipher
void ngram(char *in, char *out) {
    char *ngrams[][2] = {
        {"TH", "XA"}, {"HE", "XB"}, {"IN", "XC"}, {"ER", "XD"}, {"AN", "XE"},
        {"RE", "XF"}, {"ND", "XG"}, {"ON", "XH"}, {"EN", "XI"}, {"AT", "XJ"}
    };
    int len = strlen(in), idx = 0;
    if (len % 2) {
        char temp[MAX];
        strcpy(temp, in);
        strcat(temp, "X");
        len++;
        for (int i = 0; i < len; i++) {
            in[i] = temp[i];
        }
    }
    for (int i = 0; i < len; i += 2) {
        char bigram[3] = {toupper(in[i]), toupper(in[i + 1]), '\0'};
        int replaced = 0;
        for (int j = 0; j < 10; j++) {
            if (!strcmp(bigram, ngrams[j][0])) {
                out[idx++] = ngrams[j][1][0];
                out[idx++] = ngrams[j][1][1];
                replaced = 1;
                break;
            }
        }
        if (!replaced) {
            out[idx++] = bigram[0];
            out[idx++] = bigram[1];
        }
    }
    out[idx] = '\0';
}

// Rail Fence Cipher
void railFence(char *in, char *out, int rails) {
    int len = strlen(in), idx = 0;
    char rail[rails][len];
    memset(rail, '\n', sizeof(rail));
    int row = 0, dir_down = 0;
    for (int i = 0; i < len; i++) {
        rail[row][i] = in[i];
        if (row == 0 || row == rails - 1) dir_down = !dir_down;
        row += dir_down ? 1 : -1;
    }
    for (int i = 0; i < rails; i++)
        for (int j = 0; j < len; j++)
            if (rail[i][j] != '\n') out[idx++] = rail[i][j];
    out[idx] = '\0';
}

// Route Cipher
void route(char *in, char *out, int rows, int cols) {
    char mat[rows][cols];
    int len = strlen(in);
    int k = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            if (k < len) {
                mat[i][j] = in[k++];
            } else {
                mat[i][j] = 'X'; // Pad with 'X' if input is shorter
            }
        }
    }
    int index = 0, top = 0, bottom = rows - 1, left = 0, right = cols - 1;
    while (top <= bottom && left <= right) {
        for (int i = left; i <= right; i++) out[index++] = mat[top][i];
        top++;
        if (top > bottom || left > right) break;
        for (int i = top; i <= bottom; i++) out[index++] = mat[i][right];
        right--;
        if (top > bottom || left > right) break;
        for (int i = right; i >= left; i--) out[index++] = mat[bottom][i];
        bottom--;
        if (top > bottom || left > right) break;
        for (int i = bottom; i >= top; i--) out[index++] = mat[i][left];
        left++;
    }
    out[index] = '\0';
}

// Myszkowski Cipher
void myszkowski(char *in, char *out, char *key) {
    int len = strlen(in), klen = strlen(key), rows = (len + klen - 1) / klen;
    char mat[rows][klen];
    memset(mat, 'X', sizeof(mat));
    for (int i = 0, idx = 0; i < rows && idx < len; i++)
        for (int j = 0; j < klen && idx < len; j++)
            mat[i][j] = in[idx++];

    char sortedKey[MAX];
    strcpy(sortedKey, key);
    // Sort the key numerically
    for (int i = 0; i < klen - 1; i++) {
        for (int j = 0; j < klen - i - 1; j++) {
            if (key[j] > key[j + 1]) {
                char temp = key[j];
                key[j] = key[j + 1];
                key[j + 1] = temp;
            }
        }
    }

    int out_idx = 0;
    for (char ch = '0'; ch <= '9'; ch++) {
        for (int col = 0; col < klen; col++) {
            if (sortedKey[col] == ch) {
                for (int row = 0; row < rows; row++) {
                    out[out_idx++] = mat[row][col];
                }
            }
        }
    }
    out[out_idx] = '\0';
}

// === Main ===
int main() {
    int mode, shift, a, b, rails, rows, cols;
    char input[MAX], output[MAX], key[MAX], num_key[MAX];

    // Caesar
    printf("Caesar Cipher:\n");
    strcpy(input, "HELLO"); shift = 3; mode = 1;
    caesar(input, output, shift); printf("  Encrypted: %s\n", output);
    caesar(output, input, -shift); printf("  Decrypted: %s\n", input);

    // Atbash
    printf("\nAtbash Cipher:\n");
    strcpy(input, "HELLO");
    atbash(input, output); printf("  Encrypted: %s\n", output);
    atbash(output, input); printf("  Decrypted: %s\n", input);

    // August (Caesar shift 1)
    printf("\nAugust Cipher:\n");
    strcpy(input, "HELLO"); mode = 1;
    caesar(input, output, 1); printf("  Encrypted: %s\n", output);
    caesar(output, input, -1); printf("  Decrypted: %s\n", input);

    // Affine
    printf("\nAffine Cipher:\n");
    strcpy(input, "HELLO"); a = 5; b = 7; mode = 1;
    affine(input, output, a, b, 0); printf("  Encrypted: %s\n", output);
    strcpy(input, output); mode = 2;
    affine(input, output, a, b, 1); printf("  Decrypted: %s\n", output);

    // Vigenere
    printf("\nVigenere Cipher:\n");
    strcpy(input, "HELLO"); strcpy(key, "KEY"); mode = 1;
    polySub(input, output, key, 0, 0, 0); printf("  Encrypted: %s\n", output);

    // Gronsfeld
    printf("\nGronsfeld Cipher:\n");
    strcpy(input, "HELLO"); strcpy(num_key, "314"); mode = 1;
    polySub(input, output, num_key, 0, 1, 0); printf("  Encrypted: %s\n", output);

    // Beaufort
    printf("\nBeaufort Cipher:\n");
    strcpy(input, "HELLO"); strcpy(key, "KEY");
    beaufort(input, output, key); printf("  Encrypted: %s\n", output);

    // Autoclave
    printf("\nAutoclave Cipher:\n");
    strcpy(input, "HELLO"); strcpy(key, "KEY"); mode = 1;
    polySub(input, output, key, 0, 0, 1); printf("  Encrypted: %s\n", output);

    // NGram
    printf("\nNGram Cipher:\n");
    strcpy(input, "THIS IS A TEST"); mode = 1;
    ngram(input, output); printf("  Encrypted: %s\n", output);

    // Rail Fence
    printf("\nRail Fence Cipher:\n");
    strcpy(input, "HELLO"); rails = 3; mode = 1;
    railFence(input, output, rails); printf("  Encrypted: %s\n", output);

    // Route
    printf("\nRoute Cipher:\n");
    strcpy(input, "HELLO"); rows = 3; cols = 4; mode = 1;
    route(input, output, rows, cols); printf("  Encrypted: %s\n", output);

    // Myszkowski
    printf("\nMyszkowski Cipher:\n");
    strcpy(input, "HELLO"); strcpy(num_key, "314"); mode = 1;
    myszkowski(input, output, num_key); printf("  Encrypted: %s\n", output);

    return 0;
}
