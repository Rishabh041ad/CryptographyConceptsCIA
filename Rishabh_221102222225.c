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
            out[i] = (in[i] - base + shift) % 26 + base;
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
    if (len % 2) strcat(in, "X");
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
    int k = 0;
    for (int i = 0; i < rows && k < strlen(in); i++)
        for (int j = 0; j < cols && k < strlen(in); j++)
            mat[i][j] = in[k++];
    int index = 0, top = 0, bottom = rows - 1, left = 0, right = cols - 1;
    while (top <= bottom && left <= right) {
        for (int i = left; i <= right; i++) out[index++] = mat[top][i];
        top++;
        for (int i = top; i <= bottom; i++) out[index++] = mat[i][right];
        right--;
        for (int i = right; i >= left; i--) out[index++] = mat[bottom][i];
        bottom--;
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
    int idx = 0;
    for (char ch = '1'; ch <= '9'; ch++) {
        for (int col = 0; col < klen; col++) {
            if (key[col] == ch)
                for (int row = 0; row < rows; row++)
                    out[idx++] = mat[row][col];
        }
    }
    out[idx] = '\0';
}

// === Main ===
int main() {
    int choice, mode, shift, a, b, rails, rows, cols;
    char input[MAX], output[MAX], key[MAX];

    printf("Select Mode:\n1. Encrypt\n2. Decrypt\nChoice: ");
    scanf("%d", &mode); getchar();

    printf("\nSelect Cipher:\n1.Caesar\n2.Atbash\n3.August\n4.Affine\n5.Vigenere\n");
    printf("6.Gronsfeld\n7.Beaufort\n8.Autoclave\n9.NGram\n10.Hill (NA)\n11.Rail Fence\n12.Route\n13.Myszkowski\nChoice: ");
    scanf("%d", &choice); getchar();

    printf("\nEnter text: ");
    fgets(input, MAX, stdin);
    input[strcspn(input, "\n")] = 0;

    switch (choice) {
        case 1: printf("Enter shift: "); scanf("%d", &shift);
                caesar(input, output, mode == 1 ? shift : -shift); break;
        case 2: atbash(input, output); break;
        case 3: caesar(input, output, mode == 1 ? 1 : -1); break;
        case 4: printf("Enter a (coprime to 26) and b: "); scanf("%d%d", &a, &b);
                affine(input, output, a, b, mode == 2); break;
        case 5: printf("Enter key: "); scanf("%s", key);
                polySub(input, output, key, mode == 2, 0, 0); break;
        case 6: printf("Enter numeric key: "); scanf("%s", key);
                polySub(input, output, key, mode == 2, 1, 0); break;
        case 7: printf("Enter key: "); scanf("%s", key);
                beaufort(input, output, key); break;
        case 8: printf("Enter key: "); scanf("%s", key);
                polySub(input, output, key, mode == 2, 0, 1); break;
        case 9: if (mode == 2) { printf("Decryption not supported.\n"); return 1; }
                ngram(input, output); break;
        case 10: printf("Hill cipher not implemented.\n"); return 1;
        case 11: printf("Enter rails: "); scanf("%d", &rails);
                 if (mode == 1) railFence(input, output, rails);
                 else { printf("Rail Fence decryption not implemented.\n"); return 1; } break;
        case 12: printf("Enter rows and cols: "); scanf("%d%d", &rows, &cols);
                 if (mode == 1) route(input, output, rows, cols);
                 else { printf("Route decryption not implemented.\n"); return 1; } break;
        case 13: printf("Enter numeric key: "); scanf("%s", key);
                 if (mode == 1) myszkowski(input, output, key);
                 else { printf("Myszkowski decryption not implemented.\n"); return 1; } break;
        default: printf("Invalid choice.\n"); return 1;
    }

    printf("\nResult: %s\n", output);
    return 0;
}
