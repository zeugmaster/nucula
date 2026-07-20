#include "commands.h"
#include "console.h"
#include "wallet.hpp"
#include "wallet_store.hpp"
#include "bip39.h"
#include "display.h"
#include "ui.h"

#include <cstring>

// -------------------------------------------------------------------------
// Seed management (NUT-13)
// -------------------------------------------------------------------------

static void erase_all_wallets()
{
    wallet_store_guard guard;
    wallet_store_remove_all();
}

static void cmd_seed(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0 || strcmp(arg, "show") == 0) {
        std::string mnemonic;
        if (cashu::Wallet::load_mnemonic(mnemonic)) {
            nucula_console_write("WARNING: keep your seed phrase secret!\r\n");
            nucula_console_write(mnemonic.c_str());
            nucula_console_write("\r\n");
        } else {
            nucula_console_write("no seed configured\r\n");
        }
        return;
    }

    if (strcmp(arg, "generate") == 0) {
        char mnemonic[256];
        if (!bip39_generate(mnemonic, sizeof(mnemonic))) {
            nucula_console_write("ERROR: mnemonic generation failed\r\n");
            return;
        }

        unsigned char seed[64];
        if (!bip39_to_seed(mnemonic, seed)) {
            nucula_console_write("ERROR: seed derivation failed\r\n");
            return;
        }

        erase_all_wallets();
        cashu::Wallet::erase_seed();

        if (!cashu::Wallet::save_seed(seed, mnemonic)) {
            nucula_console_write("ERROR: failed to save seed\r\n");
            return;
        }

        nucula_console_write("seed generated. write down your seed phrase:\r\n\r\n");
        nucula_console_write(mnemonic);
        nucula_console_write("\r\n\r\nall wallet data erased. add mints with 'mint add <url>'\r\n");
        display_refresh();
        return;
    }

    if (strncmp(arg, "restore ", 8) == 0) {
        const char *words = arg + 8;
        while (*words == ' ') words++;

        if (!bip39_validate(words)) {
            nucula_console_write("ERROR: invalid mnemonic (bad checksum or unknown words)\r\n");
            return;
        }

        unsigned char seed[64];
        if (!bip39_to_seed(words, seed)) {
            nucula_console_write("ERROR: seed derivation failed\r\n");
            return;
        }

        erase_all_wallets();
        cashu::Wallet::erase_seed();

        if (!cashu::Wallet::save_seed(seed, words)) {
            nucula_console_write("ERROR: failed to save seed\r\n");
            return;
        }

        nucula_console_write("seed restored. all wallet data erased.\r\n");
        nucula_console_write("add mints with 'mint add <url>' to begin recovery\r\n");
        display_refresh();
        return;
    }

    if (strcmp(arg, "wipe") == 0) {
        erase_all_wallets();
        cashu::Wallet::erase_seed();
        nucula_console_write("seed and all wallet data erased\r\n");
        display_refresh();
        return;
    }

    nucula_console_write("usage: seed [show|generate|restore <12 words>|wipe]\r\n");
}

void commands_seed_register(void)
{
    console_register_cmd("seed",    cmd_seed,     "seed [show|generate|restore|wipe]");
}
